"""ImagePullBackOff diagnostic plugin."""
from kubernetes import client as k8s


class ImagePullDiagnostic:
    issue_type = "image-pull"

    def diagnose(self, core: k8s.CoreV1Api, pod) -> dict:
        images = []
        for c in (pod.spec.containers or []):
            images.append({
                "container": c.name,
                "image": c.image,
                "pull_policy": c.image_pull_policy or "default",
            })

        pull_secrets_info = []
        pull_secrets = pod.spec.image_pull_secrets or []
        for s in pull_secrets:
            # Existence is not checked: reading a Secret returns its contents (registry credentials),
            # and the monitor has no access to Secrets by design. The kubelet's pull error already
            # says whether authentication failed.
            pull_secrets_info.append({"name": s.name, "exists": "not checked (no Secret access by design)"})

        data = {"images": images}
        if pull_secrets_info:
            data["pull_secrets"] = pull_secrets_info
        elif not pull_secrets:
            data["pull_secrets_configured"] = False
        return data
