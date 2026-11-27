# Smoke fixture (#101 PR-B): cố ý sai cấu hình để checkov / trivy-iac phải báo.
resource "aws_s3_bucket" "public" {
  bucket = "vulnguard-smoke-public"
  acl    = "public-read"
}
