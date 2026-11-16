# ---------------------------------------------------------------------------
# App delivery via S3. We zip the backend/ folder and upload it to a private
# bucket; each EC2 instance downloads and unzips it on boot (see user_data.sh).
# This keeps the deploy self-contained — no GitHub credentials on the instances.
# ---------------------------------------------------------------------------

resource "random_id" "bucket_suffix" {
  byte_length = 4
}

resource "aws_s3_bucket" "app" {
  bucket        = "${var.project}-app-${random_id.bucket_suffix.hex}"
  force_destroy = true # allow `terraform destroy` to remove the bucket + objects
}

resource "aws_s3_bucket_public_access_block" "app" {
  bucket                  = aws_s3_bucket.app.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

data "archive_file" "app_bundle" {
  type        = "zip"
  source_dir  = "${path.module}/../../backend"
  output_path = "${path.module}/.app_bundle.zip"
}

resource "aws_s3_object" "app_bundle" {
  bucket = aws_s3_bucket.app.id
  key    = "app.zip"
  source = data.archive_file.app_bundle.output_path
  etag   = data.archive_file.app_bundle.output_md5
}
