output "repository_id" {
  description = "The Artifact Registry repository_id (= name_prefix). The adopter's deploy-time mirror of the verified, signed sandbox image lands at \"<repository_url>/<image>:<tag>\" here."
  value       = google_artifact_registry_repository.sandbox.repository_id
}

output "repository_url" {
  description = "The pushable/pullable base path of the repository, \"<region>-docker.pkg.dev/<project>/<repository_id>\". Append \"/<image>@sha256:...\" to form the digest-pinned reference the (forthcoming) providers/cloud-gcp Config.SandboxImage will consume — that field is not yet built."
  value       = "${google_artifact_registry_repository.sandbox.location}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.sandbox.repository_id}"
}
