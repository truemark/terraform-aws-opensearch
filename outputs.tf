output "arn" {
  value = aws_elasticsearch_domain.opensearch.arn
}

output "domain_id" {
  value = aws_elasticsearch_domain.opensearch.domain_id
}

output "domain_name" {
  value = aws_elasticsearch_domain.opensearch.domain_name
}

output "endpoint" {
  value = aws_elasticsearch_domain.opensearch.endpoint
}

output "kibana_endpoint" {
  value = aws_elasticsearch_domain.opensearch.kibana_endpoint
}
