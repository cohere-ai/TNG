# Builds every image in one BuildKit session so the shared stages, the cargo build above all, run
# once. Run from the repository root. CI passes the bare tags from docker/metadata-action in TAGS,
# newline separated, and its labels through the docker-metadata-action target.

variable "REGISTRY" {
  default = "ghcr.io/cohere-ai"
}

variable "TAGS" {
  default = "local"
}

target "docker-metadata-action" {}

target "image" {
  name       = tgt
  matrix     = { tgt = ["tng", "tng-ita", "tng-trustee", "tng-ingress"] }
  inherits   = ["docker-metadata-action"]
  context    = "."
  dockerfile = "cohere/docker/Dockerfile"
  target     = tgt
  tags       = [for t in split("\n", trimspace(TAGS)) : "${REGISTRY}/${tgt}:${trimspace(t)}"]
}

group "default" {
  targets = ["image"]
}
