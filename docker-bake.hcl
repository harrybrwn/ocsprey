variable "VERSION" {
	default = "latest"
}

variable "GITHUB_SHA" {}

group "default" {
	targets = [
		"ocsprey",
	]
}

target "ocsprey" {
	dockerfile = "Dockerfile"
	context = "."
	tags = [
		"harrybrwn/ocsprey:latest",
		"harrybrwn/ocsprey:${VERSION}",
		notequal("", GITHUB_SHA) ? "harrybrwn/ocsprey:${GITHUB_SHA}" : "",
	]
	platforms = [
		"linux/amd64",
		"linux/arm64",
		"linux/arm/v7",
	]
}