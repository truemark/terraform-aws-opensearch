variable "account_id" {
  description = "The account id where the services reside."
  type        = number
}

variable "advanced_security_options" {
  description = "Toggle creation of fine grained access control."
  type        = bool
  default     = true
}

variable "allowed_cidr_blocks" {
  description = "A list of CIDR blocks which are allowed to access the Opensearch domain."
  type        = list(string)
  default     = ["10.0.0.0/8"]
}

variable "archive_bucket_name" {
  description = "The name of the archive bucket associated with this Opensearch domain."
  type        = string
}

variable "dedicated_master_enabled" {
  description = "Whether dedicated main nodes are enabled for the cluster."
  type        = bool
  default     = false
}

variable "ebs_enabled" {
  description = "Whether EBS volumes are attached to data nodes in the domain."
  type        = bool
  default     = true
}

variable "elasticsearch_version" {
  description = "The specific engine version to implement. Default is OpenSearch_1.3."
  type        = string
  default     = "OpenSearch_1.3"
}

variable "encrypt_at_rest" {
  description = "Whether or not to enforce encryption at rest. Only available for certain instance types."
  type        = bool
  default     = true
}

variable "enforce_https" {
  description = "Whether or not to require HTTPS."
  type        = bool
  default     = true
}

variable "include_numbers" {
  description = "Whether or not to include numbers in the password."
  type        = bool
  default     = true
}

variable "instance_type" {
  description = "The instance type configuration for Opensearch nodes."
  type        = string
}

variable "internal_user_database_enabled" {
  description = "Whether the internal user database is enabled."
  type        = bool
  default     = false
}

variable "kms_key_id" {
  description = "The key to use to encrypt the cluster."
  type        = string
}

variable "master_user_name" {
  description = "Name of the master user within this Opensearch cluster."
  type        = string
  default     = "root"
}

variable "name" {
  description = "The name of the Opensearch domain to create."
  type        = string
}

variable "node_to_node_encryption" {
  description = "Whether to enable node-to-node encryption. If the node_to_node_encryption block is not provided then this defaults to false."
  type        = bool
  default     = true
}

variable "password_length" {
  description = "Length of the password to generate."
  type        = number
  default     = 12
}

variable "subnet_ids" {
  description = "List of subnet IDs to use."
  type        = string
}

variable "tags" {
  description = "A map of tags to add to all resources."
  type        = map(string)
  default     = {}
}

variable "tls_security_policy" {
  description = "Name of the TLS security policy that needs to be applied to the HTTPS endpoint. Valid values: Policy-Min-TLS-1-0-2019-07 and Policy-Min-TLS-1-2-2019-07."
  type        = string
  default     = "Policy-Min-TLS-1-2-2019-07"
}

variable "volume_size" {
  description = "Size of EBS volumes attached to data nodes (in GiB)"
  type        = number
  default     = 100
}

variable "volume_type" {
  description = "Type of EBS volumes attached to data nodes."
  type        = string
  default     = "gp3"
}

variable "vpc_id" {
  description = "The ID of the VPC to provision into."
  type        = string
}
