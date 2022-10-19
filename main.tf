data "aws_iam_roles" "admin" {
  name_regex = "AWSReservedSSO_DataSystemsEngineer*"
}

data "aws_iam_policy_document" "access" {
  version = "2012-10-17"
  statement {
    effect    = "Allow"
    actions   = ["es:*"]
    resources = ["arn:aws:es:*:${var.account_id}:domain/${var.name}/*"]
    principals {
      identifiers = ["*"]
      type        = "AWS"
    }
  }
}

# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticsearch_domain
resource "aws_elasticsearch_domain" "opensearch" {
  domain_name           = var.name
  elasticsearch_version = "OpenSearch_1.3"
  tags                  = var.tags
  depends_on            = [aws_iam_service_linked_role.es]

  cluster_config {
    instance_type            = var.instance_type
    instance_count           = 1
    dedicated_master_enabled = var.dedicated_master_enabled
  }

  vpc_options {
    subnet_ids = [var.subnet_ids]

    security_group_ids = [aws_security_group.es.id]
  }

  node_to_node_encryption {
    enabled = var.node_to_node_encryption
  }

  encrypt_at_rest {
    enabled    = var.encrypt_at_rest
    kms_key_id = var.kms_key_id
    # kms_key_id = "arn:aws:kms:us-west-2:${local.account_number}:alias/yleo-opensearch"
  }

  domain_endpoint_options {
    enforce_https       = var.enforce_https
    tls_security_policy = var.tls_security_policy
  }

  ebs_options {
    ebs_enabled = var.ebs_enabled
    volume_type = var.volume_type
    volume_size = var.volume_size
  }

  advanced_security_options {
    enabled                        = var.advanced_security_options
    internal_user_database_enabled = var.internal_user_database_enabled
    master_user_options {
      # master_user_arn      = join("",data.aws_iam_roles.root.arns)
      master_user_name     = var.master_user_name
      master_user_password = random_password.root.result
    }

  }

  access_policies = data.aws_iam_policy_document.access.json

  log_publishing_options {
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.logging.arn
    log_type                 = "INDEX_SLOW_LOGS"
  }

  log_publishing_options {
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.logging.arn
    log_type                 = "SEARCH_SLOW_LOGS"
  }

  log_publishing_options {
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.logging.arn
    log_type                 = "ES_APPLICATION_LOGS"
  }

  log_publishing_options {
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.logging.arn
    log_type                 = "AUDIT_LOGS"
  }
}

# Figure out how to allow this in the code even if it already exists. AWS creates
# this role in the background ? 
resource "aws_iam_service_linked_role" "es" {
  count            = 1
  aws_service_name = "es.amazonaws.com"
  description      = "Allows Amazon ES to manage AWS resources for a domain on your behalf."
}

resource "aws_security_group" "es" {
  name        = var.name
  description = "Security group protecting Opensearch domain ${var.name}. Managed by Terraform."
  vpc_id      = var.vpc_id

  ingress {
    from_port = 443
    to_port   = 443
    protocol  = "tcp"

    cidr_blocks = var.allowed_cidr_blocks

  }

  ingress {
    from_port = 9200
    to_port   = 9200
    protocol  = "tcp"

    cidr_blocks = var.allowed_cidr_blocks

  }
  tags = var.tags
}

resource "aws_cloudwatch_log_group" "logging" {
  name = var.name
  tags = var.tags
}

resource "aws_cloudwatch_log_resource_policy" "logging" {
  policy_name = var.name

  policy_document = <<CONFIG
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "es.amazonaws.com"
      },
      "Action": [
        "logs:PutLogEvents",
        "logs:PutLogEventsBatch",
        "logs:CreateLogStream"
      ],
      "Resource": "arn:aws:logs:*"
    }
  ]
}
CONFIG
}
#--------------------------------------------------------------------
# Add the master secret, generate the password and add it to the local 
# security db definition above. 
# Special characters are _required_ by Opensearch. I'm hard coding the
# variable value in the random password resource to avoid confusion.

resource "random_password" "root" {
  # count       = var.create ? 1 : 0
  length    = var.password_length
  special   = true
  min_upper = 2
  min_lower = 2
  numeric   = true
}

resource "aws_secretsmanager_secret" "root" {
  # count       = var.create ? 1 : 0
  name_prefix = "database/${var.name}/master-"
  description = "Master account password on ${var.name}"
  tags        = var.tags
}

resource "aws_secretsmanager_secret_version" "root" {
  # count     = var.create ? 1 : 0
  secret_id = aws_secretsmanager_secret.root.id
  secret_string = jsonencode({
    # host           = var.host
    # port           = var.port
    # dbname         = var.dbname
    username = "root"
    # connect_string = var.connect_string
    engine   = "Opensearch"
    password = random_password.root.result
  })
}

