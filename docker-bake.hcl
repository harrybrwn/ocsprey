variable "VERSION" {
	default = "latest"
}

variable "CI" {}
variable "GITHUB_SHA" {}
variable "GITHUB_REF_TYPE" {}
variable "GITHUB_REF_NAME" {}

group "default" {
	targets = [
		"ocsprey",
	]
}

target "ocsprey" {
	dockerfile = "Dockerfile"
	context    = "."
	tags = [
		"harrybrwn/ocsprey:latest",
		"harrybrwn/ocsprey:${VERSION}",
		notequal("", GITHUB_SHA) ? "harrybrwn/ocsprey:${GITHUB_SHA}" : "",
		(
		  notequal("", GITHUB_REF_NAME) &&
		  notequal("main", GITHUB_REF_NAME)
		  ? "harrybrwn/ocsprey:${GITHUB_REF_NAME}"
		  : ""
		)
	]
	platforms = [
		"linux/amd64",
		"linux/arm64",
		"linux/arm/v7",
		"linux/arm/v6",
	]
	labels = {
		maintainer   = "Harry Brown"
		version      = equal(VERSION, "") && equal(GITHUB_REF_TYPE, "tag") ? GITHUB_REF_NAME : VERSION
		"git.commit" = GITHUB_SHA
	}
}