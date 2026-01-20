# test-09-edge-cases.tf
# Tests 40-74: S3 General Purpose Bucket Edge Cases
# These tests validate Warden's ability to handle edge cases that could break proxying

################################################################################
# Main Edge Cases Bucket
################################################################################

resource "aws_s3_bucket" "edge_cases" {
  bucket        = "${local.bucket_prefix}-edge-cases"
  force_destroy = true

  tags = {
    Name        = "Edge Cases Test Bucket"
    TestNumber  = "40-74"
    Description = "Tests S3 edge cases for Warden proxy"
  }
}

################################################################################
# Category A: Special Characters in Object Keys (Tests 40-49)
################################################################################

# Test 40: Spaces in object key
resource "aws_s3_object" "key_with_spaces" {
  bucket       = aws_s3_bucket.edge_cases.id
  key          = "path with spaces/file name.txt"
  content      = "Object key contains spaces"
  content_type = "text/plain"

  tags = {
    TestNumber  = "40"
    Description = "Spaces in object key"
  }
}

# Test 41: Unicode characters (UTF-8)
resource "aws_s3_object" "key_unicode_cafe" {
  bucket       = aws_s3_bucket.edge_cases.id
  key          = "international/café/menu.txt"
  content      = "French café menu"
  content_type = "text/plain; charset=utf-8"

  tags = {
    TestNumber  = "41a"
    Description = "Unicode - French accents"
  }
}

resource "aws_s3_object" "key_unicode_chinese" {
  bucket       = aws_s3_bucket.edge_cases.id
  key          = "international/中文/文件.txt"
  content      = "Chinese characters in path"
  content_type = "text/plain; charset=utf-8"

  tags = {
    TestNumber  = "41b"
    Description = "Unicode - Chinese characters"
  }
}

resource "aws_s3_object" "key_unicode_russian" {
  bucket       = aws_s3_bucket.edge_cases.id
  key          = "international/русский/файл.txt"
  content      = "Russian characters in path"
  content_type = "text/plain; charset=utf-8"

  tags = {
    TestNumber  = "41c"
    Description = "Unicode - Russian Cyrillic"
  }
}

resource "aws_s3_object" "key_unicode_arabic" {
  bucket       = aws_s3_bucket.edge_cases.id
  key          = "international/العربية/ملف.txt"
  content      = "Arabic characters in path"
  content_type = "text/plain; charset=utf-8"

  tags = {
    TestNumber  = "41d"
    Description = "Unicode - Arabic"
  }
}

resource "aws_s3_object" "key_unicode_emoji" {
  bucket       = aws_s3_bucket.edge_cases.id
  key          = "emoji/🎉🚀💻/party.txt"
  content      = "Emoji in path"
  content_type = "text/plain; charset=utf-8"

  tags = {
    TestNumber  = "41e"
    Description = "Unicode - Emoji"
  }
}

# Test 42: URL-reserved characters (? and &)
# Note: These are valid in S3 keys but tricky for URL handling
resource "aws_s3_object" "key_question_mark" {
  bucket       = aws_s3_bucket.edge_cases.id
  key          = "special/what?is?this.txt"
  content      = "Question marks in key"
  content_type = "text/plain"

  tags = {
    TestNumber  = "42a"
    Description = "Question marks in key"
  }
}

resource "aws_s3_object" "key_ampersand" {
  bucket       = aws_s3_bucket.edge_cases.id
  key          = "special/tom&jerry/file.txt"
  content      = "Ampersand in key"
  content_type = "text/plain"

  tags = {
    TestNumber  = "42b"
    Description = "Ampersand in key"
  }
}

# Test 43: Hash/fragment character
resource "aws_s3_object" "key_hash" {
  bucket       = aws_s3_bucket.edge_cases.id
  key          = "special/file#section.txt"
  content      = "Hash character in key"
  content_type = "text/plain"

  tags = {
    TestNumber  = "43"
    Description = "Hash character in key"
  }
}

# Test 44: Colons (signature-sensitive - used in ARNs and timestamps)
resource "aws_s3_object" "key_colons" {
  bucket       = aws_s3_bucket.edge_cases.id
  key          = "timestamps/12:30:45/event.txt"
  content      = "Colons in key (like timestamps)"
  content_type = "text/plain"

  tags = {
    TestNumber  = "44a"
    Description = "Colons in key - timestamps"
  }
}

resource "aws_s3_object" "key_many_colons" {
  bucket       = aws_s3_bucket.edge_cases.id
  key          = "colons/a:b:c:d:e:f:g/file.txt"
  content      = "Multiple colons in key"
  content_type = "text/plain"

  tags = {
    TestNumber  = "44b"
    Description = "Multiple colons in key"
  }
}

# Test 45: Plus signs (often confused with spaces in URL encoding)
resource "aws_s3_object" "key_plus" {
  bucket       = aws_s3_bucket.edge_cases.id
  key          = "math/1+1=2/formula.txt"
  content      = "Plus sign in key"
  content_type = "text/plain"

  tags = {
    TestNumber  = "45"
    Description = "Plus sign in key"
  }
}

# Test 46: Percent signs (encoding edge case - must not double-encode)
resource "aws_s3_object" "key_percent" {
  bucket       = aws_s3_bucket.edge_cases.id
  key          = "discount/50%off/sale.txt"
  content      = "Percent sign in key"
  content_type = "text/plain"

  tags = {
    TestNumber  = "46"
    Description = "Percent sign in key"
  }
}

# Test 47: Multiple consecutive special characters
resource "aws_s3_object" "key_consecutive_slashes" {
  bucket       = aws_s3_bucket.edge_cases.id
  key          = "path///triple-slash/file.txt"
  content      = "Triple slashes in path"
  content_type = "text/plain"

  tags = {
    TestNumber  = "47a"
    Description = "Multiple consecutive slashes"
  }
}

resource "aws_s3_object" "key_consecutive_dots" {
  bucket       = aws_s3_bucket.edge_cases.id
  key          = "path/with...dots/file.txt"
  content      = "Multiple dots in path"
  content_type = "text/plain"

  tags = {
    TestNumber  = "47b"
    Description = "Multiple consecutive dots"
  }
}

resource "aws_s3_object" "key_mixed_special" {
  bucket       = aws_s3_bucket.edge_cases.id
  key          = "mixed/---___...---/file.txt"
  content      = "Mixed special chars"
  content_type = "text/plain"

  tags = {
    TestNumber  = "47c"
    Description = "Mixed consecutive special chars"
  }
}

# Test 48: Long object key (S3 supports up to 1024 bytes)
resource "aws_s3_object" "key_long" {
  bucket       = aws_s3_bucket.edge_cases.id
  key          = "long/${join("/", [for i in range(50) : "segment${i}"])}/file.txt"
  content      = "Long path with many segments"
  content_type = "text/plain"

  tags = {
    TestNumber  = "48"
    Description = "Long object key with many segments"
  }
}

# Test 49: Object key with leading/trailing special chars
resource "aws_s3_object" "key_leading_space" {
  bucket       = aws_s3_bucket.edge_cases.id
  key          = " leading-space/file.txt"
  content      = "Leading space in first segment"
  content_type = "text/plain"

  tags = {
    TestNumber  = "49a"
    Description = "Leading space in path"
  }
}

resource "aws_s3_object" "key_trailing_space" {
  bucket       = aws_s3_bucket.edge_cases.id
  key          = "trailing-space /file.txt"
  content      = "Trailing space in segment"
  content_type = "text/plain"

  tags = {
    TestNumber  = "49b"
    Description = "Trailing space in path"
  }
}

################################################################################
# Category B: Path Variations (Tests 50-54)
################################################################################

# Test 50: Deep nested path (16+ levels)
resource "aws_s3_object" "deep_path" {
  bucket       = aws_s3_bucket.edge_cases.id
  key          = "a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/q/r/s/t/deep.txt"
  content      = "Very deeply nested file (20 levels)"
  content_type = "text/plain"

  tags = {
    TestNumber  = "50"
    Description = "Deep nested path - 20 levels"
  }
}

# Test 51: Trailing slash (folder-like object)
resource "aws_s3_object" "trailing_slash" {
  bucket       = aws_s3_bucket.edge_cases.id
  key          = "folder-object/"
  content      = ""
  content_type = "application/x-directory"

  tags = {
    TestNumber  = "51"
    Description = "Trailing slash - folder-like object"
  }
}

# Test 52: Root-level object (no path)
resource "aws_s3_object" "root_level" {
  bucket       = aws_s3_bucket.edge_cases.id
  key          = "rootfile.txt"
  content      = "File at root level"
  content_type = "text/plain"

  tags = {
    TestNumber  = "52"
    Description = "Root-level object"
  }
}

# Test 53: Hidden file (dot prefix)
resource "aws_s3_object" "hidden_file" {
  bucket       = aws_s3_bucket.edge_cases.id
  key          = ".hidden/dir/.gitignore"
  content      = "# Hidden gitignore file"
  content_type = "text/plain"

  tags = {
    TestNumber  = "53"
    Description = "Hidden file with dot prefix"
  }
}

# Test 54: Object key with consecutive slashes (S3 preserves these)
resource "aws_s3_object" "consecutive_slashes" {
  bucket       = aws_s3_bucket.edge_cases.id
  key          = "path//with///multiple////slashes/file.txt"
  content      = "Key contains consecutive slashes"
  content_type = "text/plain"

  tags = {
    TestNumber  = "54"
    Description = "Consecutive slashes in key"
  }
}

################################################################################
# Category C: Content Types & Encoding (Tests 55-59)
################################################################################

# Test 55: Binary content (base64)
resource "aws_s3_object" "binary_png" {
  bucket = aws_s3_bucket.edge_cases.id
  key    = "binary/1x1-pixel.png"
  # Minimal valid PNG (1x1 transparent pixel)
  content_base64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
  content_type   = "image/png"

  tags = {
    TestNumber  = "55"
    Description = "Binary PNG content"
  }
}

# Test 56: Large text file (>100KB)
resource "aws_s3_object" "large_text" {
  bucket       = aws_s3_bucket.edge_cases.id
  key          = "large/bigfile.txt"
  content      = join("\n", [for i in range(1024) : "Line ${i}: This is a test line with some content to make the file larger. Random hash: ${md5(tostring(i))} | Padding: ${md5(tostring(i + 1000))}${md5(tostring(i + 2000))}"])
  content_type = "text/plain"

  tags = {
    TestNumber  = "56"
    Description = "Large text file over 100KB"
  }
}

# Test 57: Empty object (zero bytes)
resource "aws_s3_object" "empty" {
  bucket       = aws_s3_bucket.edge_cases.id
  key          = "empty/zero-bytes.txt"
  content      = ""
  content_type = "text/plain"

  tags = {
    TestNumber  = "57"
    Description = "Empty zero-byte object"
  }
}

# Test 58: Single byte object
resource "aws_s3_object" "single_byte" {
  bucket       = aws_s3_bucket.edge_cases.id
  key          = "tiny/one-byte.txt"
  content      = "X"
  content_type = "text/plain"

  tags = {
    TestNumber  = "58"
    Description = "Single byte object"
  }
}

# Test 59: Object with all HTTP headers
resource "aws_s3_object" "all_headers" {
  bucket              = aws_s3_bucket.edge_cases.id
  key                 = "headers/complete.txt"
  content             = "Object with all HTTP headers set"
  content_type        = "text/plain; charset=utf-8"
  cache_control       = "max-age=31536000, immutable"
  content_disposition = "attachment; filename=\"download.txt\""
  content_encoding    = "identity"
  content_language    = "en-US"

  metadata = {
    custom_header_1 = "value1"
    custom_header_2 = "value2"
    author          = "warden-test"
  }

  tags = {
    TestNumber  = "59"
    Description = "Object with all HTTP headers"
  }
}

################################################################################
# Category D: Bucket Name Edge Cases (Tests 60-64)
################################################################################

# Test 60: Bucket name with numbers
resource "aws_s3_bucket" "all_numbers_suffix" {
  bucket        = "${local.bucket_prefix}-123456789"
  force_destroy = true

  tags = {
    TestNumber  = "60"
    Description = "Bucket with numeric suffix"
  }
}

resource "aws_s3_object" "in_numeric_bucket" {
  bucket       = aws_s3_bucket.all_numbers_suffix.id
  key          = "test.txt"
  content      = "Object in bucket with numeric suffix"
  content_type = "text/plain"
}

# Test 61: Bucket name ending in 12 digits (like AWS account ID)
# This tests that Warden doesn't confuse it with an Access Point
resource "aws_s3_bucket" "ends_12_digits" {
  bucket        = "${local.bucket_prefix}-123456789012"
  force_destroy = true

  tags = {
    TestNumber  = "61"
    Description = "Bucket ending in 12 digits - account ID pattern"
  }
}

resource "aws_s3_object" "in_12digit_bucket" {
  bucket       = aws_s3_bucket.ends_12_digits.id
  key          = "test.txt"
  content      = "Object in bucket that ends with 12 digits"
  content_type = "text/plain"
}

# Test 62: Bucket with consecutive hyphens
resource "aws_s3_bucket" "double_hyphen" {
  bucket        = "${local.bucket_prefix}--double"
  force_destroy = true

  tags = {
    TestNumber  = "62"
    Description = "Bucket with double hyphen"
  }
}

resource "aws_s3_object" "in_double_hyphen_bucket" {
  bucket       = aws_s3_bucket.double_hyphen.id
  key          = "test.txt"
  content      = "Object in bucket with double hyphen"
  content_type = "text/plain"
}

# Test 63: Bucket with dots (note: dots can cause TLS issues)
resource "aws_s3_bucket" "with_dots" {
  bucket        = "${local.bucket_prefix}.with.dots"
  force_destroy = true

  tags = {
    TestNumber  = "63"
    Description = "Bucket with dots in name"
  }
}

resource "aws_s3_object" "in_dotted_bucket" {
  bucket       = aws_s3_bucket.with_dots.id
  key          = "test.txt"
  content      = "Object in bucket with dots"
  content_type = "text/plain"
}

# Test 64: Short bucket name
resource "aws_s3_bucket" "short_name" {
  bucket        = "${local.bucket_prefix}-s"
  force_destroy = true

  tags = {
    TestNumber  = "64"
    Description = "Short bucket name"
  }
}

resource "aws_s3_object" "in_short_bucket" {
  bucket       = aws_s3_bucket.short_name.id
  key          = "test.txt"
  content      = "Object in short-named bucket"
  content_type = "text/plain"
}

################################################################################
# Category E: Operations Edge Cases (Tests 65-69)
################################################################################

# Test 65: Source object for copy tests
resource "aws_s3_object" "copy_source" {
  bucket       = aws_s3_bucket.edge_cases.id
  key          = "originals/source-file.txt"
  content      = "This is the source file for copy tests"
  content_type = "text/plain"

  tags = {
    TestNumber  = "65-source"
    Description = "Source for copy tests"
  }
}

# Test 65: Copy object (same bucket)
resource "aws_s3_object_copy" "same_bucket_copy" {
  bucket = aws_s3_bucket.edge_cases.id
  key    = "copies/copied-file.txt"
  source = "${aws_s3_bucket.edge_cases.id}/originals/source-file.txt"

  depends_on = [aws_s3_object.copy_source]

  tags = {
    TestNumber  = "65"
    Description = "Copy object same bucket"
  }
}

# Test 66: Source with unicode for copy
resource "aws_s3_object" "unicode_source" {
  bucket       = aws_s3_bucket.edge_cases.id
  key          = "café/source.txt"
  content      = "Source with unicode path"
  content_type = "text/plain"

  tags = {
    TestNumber  = "66-source"
    Description = "Unicode source for copy"
  }
}

# Test 66: Copy object with special chars in source
resource "aws_s3_object_copy" "unicode_copy" {
  bucket = aws_s3_bucket.edge_cases.id
  key    = "copies/from-unicode.txt"
  source = "${aws_s3_bucket.edge_cases.id}/café/source.txt"

  depends_on = [aws_s3_object.unicode_source]

  tags = {
    TestNumber  = "66"
    Description = "Copy from unicode path"
  }
}

# Test 67: Object with SSE-S3 encryption
resource "aws_s3_object" "sse_s3" {
  bucket                 = aws_s3_bucket.edge_cases.id
  key                    = "encrypted/sse-s3.txt"
  content                = "SSE-S3 encrypted content"
  content_type           = "text/plain"
  server_side_encryption = "AES256"

  tags = {
    TestNumber  = "67"
    Description = "SSE-S3 encrypted object"
  }
}

# Test 68: Object with SSE-KMS encryption (default key)
resource "aws_s3_object" "sse_kms" {
  bucket                 = aws_s3_bucket.edge_cases.id
  key                    = "encrypted/sse-kms.txt"
  content                = "SSE-KMS encrypted content"
  content_type           = "text/plain"
  server_side_encryption = "aws:kms"

  tags = {
    TestNumber  = "68"
    Description = "SSE-KMS encrypted object"
  }
}

# Test 69: Object with checksum
resource "aws_s3_object" "with_checksum" {
  bucket             = aws_s3_bucket.edge_cases.id
  key                = "checksum/verified.txt"
  content            = "Content with checksum verification"
  content_type       = "text/plain"
  checksum_algorithm = "SHA256"

  tags = {
    TestNumber  = "69"
    Description = "Object with SHA256 checksum"
  }
}

################################################################################
# Category F: Query String Operations (Tests 70-74)
################################################################################

# Test 70-74: These use data sources to test read operations

# Test 70: List objects with prefix
data "aws_s3_objects" "with_prefix" {
  bucket = aws_s3_bucket.edge_cases.id
  prefix = "special/"

  depends_on = [
    aws_s3_object.key_question_mark,
    aws_s3_object.key_ampersand,
    aws_s3_object.key_hash,
  ]
}

# Test 71: List objects with delimiter
data "aws_s3_objects" "with_delimiter" {
  bucket    = aws_s3_bucket.edge_cases.id
  delimiter = "/"

  depends_on = [
    aws_s3_object.key_with_spaces,
    aws_s3_object.root_level,
    aws_s3_object.deep_path,
  ]
}

# Test 72: List objects with max_keys
data "aws_s3_objects" "limited" {
  bucket   = aws_s3_bucket.edge_cases.id
  max_keys = 5

  depends_on = [
    aws_s3_object.key_with_spaces,
    aws_s3_object.key_unicode_cafe,
    aws_s3_object.key_colons,
  ]
}

# Test 73: Head object (metadata only) - basic
data "aws_s3_object" "head_basic" {
  bucket = aws_s3_bucket.edge_cases.id
  key    = aws_s3_object.all_headers.key

  depends_on = [aws_s3_object.all_headers]
}

# Test 74: Read object with unicode key
data "aws_s3_object" "read_unicode" {
  bucket = aws_s3_bucket.edge_cases.id
  key    = aws_s3_object.key_unicode_cafe.key

  depends_on = [aws_s3_object.key_unicode_cafe]
}

################################################################################
# Outputs - Verification
################################################################################

output "edge_case_bucket" {
  value       = aws_s3_bucket.edge_cases.id
  description = "Main edge cases bucket ID"
}

output "special_char_objects_created" {
  value = {
    spaces        = aws_s3_object.key_with_spaces.key
    unicode_cafe  = aws_s3_object.key_unicode_cafe.key
    unicode_zh    = aws_s3_object.key_unicode_chinese.key
    question_mark = aws_s3_object.key_question_mark.key
    colons        = aws_s3_object.key_colons.key
    plus          = aws_s3_object.key_plus.key
    percent       = aws_s3_object.key_percent.key
  }
  description = "Special character object keys created"
}

output "path_variation_objects" {
  value = {
    deep_path      = aws_s3_object.deep_path.key
    trailing_slash = aws_s3_object.trailing_slash.key
    root_level     = aws_s3_object.root_level.key
    hidden         = aws_s3_object.hidden_file.key
    consecutive_slashes = aws_s3_object.consecutive_slashes.key
  }
  description = "Path variation object keys"
}

output "bucket_name_tests" {
  value = {
    numeric_suffix = aws_s3_bucket.all_numbers_suffix.id
    ends_12_digits = aws_s3_bucket.ends_12_digits.id
    double_hyphen  = aws_s3_bucket.double_hyphen.id
    with_dots      = aws_s3_bucket.with_dots.id
    short_name     = aws_s3_bucket.short_name.id
  }
  description = "Bucket name edge case buckets"
}

output "list_with_prefix_count" {
  value       = length(data.aws_s3_objects.with_prefix.keys)
  description = "Number of objects found with prefix 'special/'"
}

output "list_with_delimiter_common_prefixes" {
  value       = data.aws_s3_objects.with_delimiter.common_prefixes
  description = "Common prefixes from delimiter listing"
}

output "head_object_metadata" {
  value = {
    content_type   = data.aws_s3_object.head_basic.content_type
    content_length = data.aws_s3_object.head_basic.content_length
    etag           = data.aws_s3_object.head_basic.etag
  }
  description = "Metadata from head object request"
}
