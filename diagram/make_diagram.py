"""Writes architecture.excaliflow (Excalidraw JSON that Excaliflow imports)."""

import json
import random
from pathlib import Path

random.seed(15)
CARBON, BLUE, PURPLE, EMERALD, AMBER, ROSE, CYAN = (
    "#171717", "#0070f3", "#7928ca", "#10b981", "#f59e0b", "#ef4444", "#06b6d4")
TINT = {BLUE: "#e6f0ff", PURPLE: "#f3e8ff", EMERALD: "#e7f8f2", AMBER: "#fff4e0", ROSE: "#fdecec",
        CYAN: "#e6f8fb", CARBON: "#f4f4f5"}
els = []


def base(kind, x, y, w, h, stroke, **kw):
    e = {"id": f"e{len(els)}", "type": kind, "x": x, "y": y, "width": w, "height": h, "angle": 0,
         "strokeColor": stroke, "backgroundColor": "transparent", "fillStyle": "solid", "strokeWidth": 2,
         "strokeStyle": "solid", "roughness": 1, "opacity": 100, "groupIds": [], "frameId": None,
         "roundness": None, "seed": random.randint(1, 2**31), "version": 1,
         "versionNonce": random.randint(1, 2**31), "isDeleted": False, "boundElements": [], "updated": 1,
         "link": None, "locked": False}
    e.update(kw)
    els.append(e)
    return e


def text(x, y, s, size=18, color=CARBON, align="left"):
    lines = s.split("\n")
    w = max(len(l) for l in lines) * size * 0.55
    h = len(lines) * size * 1.25
    if align == "center":
        x -= w / 2
    return base("text", x, y, w, h, color, strokeWidth=1, text=s, fontSize=size, fontFamily=2,
                textAlign=align, verticalAlign="top", baseline=size, containerId=None, originalText=s,
                lineHeight=1.25)


def box(x, y, w, h, color, title, sub=""):
    base("rectangle", x, y, w, h, color, backgroundColor=TINT[color], roundness={"type": 3})
    text(x + w / 2, y + 14, title, 18, CARBON, "center")
    if sub:
        text(x + w / 2, y + 42, sub, 14, "#404040", "center")


def zone(x, y, w, h, color, label):
    base("rectangle", x, y, w, h, color, strokeStyle="dashed", strokeWidth=1, roundness={"type": 3})
    text(x + 14, y + 10, label, 15, color)


def arrow(x1, y1, x2, y2, color="#525252", dashed=False):
    base("arrow", x1, y1, x2 - x1, y2 - y1, color, roundness={"type": 2},
         strokeStyle="dashed" if dashed else "solid", points=[[0, 0], [x2 - x1, y2 - y1]],
         lastCommittedPoint=None, startBinding=None, endBinding=None, startArrowhead=None,
         endArrowhead="arrow")


W, H, GAP = 220, 100, 50
COL = [60, 60 + W + GAP, 60 + 2 * (W + GAP), 60 + 3 * (W + GAP)]

text(40, 24, "container-hardening: one image, hardened, signed and locked down", 28)
text(40, 64, "Everything runs in GitHub Actions. Each control has a test; the gate, the signature and the network policy also have negative tests.",
     15, "#404040")

# Row 1: build and measure
zone(40, 100, 1070, 190, BLUE, "BUILD AND MEASURE")
y1 = 150
box(COL[0], y1, W, H, CARBON, "Juice Shop source", "codeguardian-target\n@ ad481cc (v20.3.0)")
box(COL[1], y1, W, H, BLUE, "Three images", "baseline: node:24, root\nupstream: distroless\nhardened: this repo")
box(COL[2], y1, W, H, BLUE, "Measure", "Syft packages, Trivy\nOS vs app CVEs,\nshell, code-write test")
box(COL[3], y1, W, H, AMBER, "Gate", "hardened must pass;\nbaseline and upstream\nmust fail")
for i in range(3):
    arrow(COL[i] + W + 4, y1 + H / 2, COL[i + 1] - 4, y1 + H / 2)

# Row 2: provenance, right to left
zone(40, 320, 1070, 210, PURPLE, "PROVENANCE (main branch only)")
y2 = 370
box(COL[3], y2, W, H, PURPLE, "GHCR", "pushed by digest,\nnever by tag alone")
box(COL[2], y2, W, H, PURPLE, "SBOM", "Syft, SPDX JSON,\nfrom the pushed digest")
box(COL[1], y2, W, H, PURPLE, "Cosign keyless", "sign + attest SBOM\nFulcio cert from OIDC\nentry in public Rekor")
box(COL[0], y2, W, H, EMERALD, "Verify", "exact workflow identity\n+ OIDC issuer")
text(COL[0] + W / 2 - 15, y2 + H + 12, "wrong signer, wrong issuer,\nchanged image: all refused", 14, ROSE, "center")
arrow(COL[3] + W / 2, y1 + H + 4, COL[3] + W / 2, y2 - 4)
for i in (3, 2, 1):
    arrow(COL[i] - 4, y2 + H / 2, COL[i - 1] + W + 4, y2 + H / 2)

# Row 3: run in kind
zone(40, 560, 1070, 260, EMERALD, "RUN IN KIND")
text(640, 570, "every namespace enforces restricted Pod Security", 15, EMERALD)
y3 = 620
arrow(COL[0] + W - 20, y2 + H + 4, COL[0] + W - 20, y3 - 4)
box(COL[0], y3, W, 120, CARBON, "namespace client", "label access=shop\ncurl probe")
base("rectangle", COL[1], y3, 2 * W + GAP, 170, EMERALD, backgroundColor=TINT[EMERALD], roundness={"type": 3})
text(COL[1] + W + GAP / 2, y3 + 14, "namespace shop: Juice Shop pod", 18, CARBON, "center")
text(COL[1] + W + GAP / 2, y3 + 44,
     "UID 65532, all capabilities dropped, seccomp RuntimeDefault\n"
     "read-only root; writable folders are emptyDirs seeded by node\n"
     "no service account token; default-deny NetworkPolicy\n"
     "no shell: debug with an ephemeral container", 14, "#404040", "center")
box(COL[3], y3, W, 120, ROSE, "namespace outsider", "no label\ncurl probe")
arrow(COL[0] + W + 4, y3 + 60, COL[1] - 4, y3 + 60, EMERALD)
text(COL[0] + W + GAP / 2, y3 + 70, "3000", 13, EMERALD, "center")
arrow(COL[3] - 4, y3 + 60, COL[2] + W + 4, y3 + 60, ROSE, dashed=True)
text(COL[2] + W + GAP / 2, y3 + 70, "denied", 13, ROSE, "center")
text(COL[1] + W + GAP / 2, y3 + 182,
     "egress denied: API server, internet  ·  privileged root pod refused at admission", 14, ROSE, "center")

doc = {"type": "excalidraw", "version": 2, "source": "container-hardening", "elements": els,
       "appState": {"gridSize": None, "viewBackgroundColor": "#ffffff"}, "files": {}}
Path(__file__).with_name("architecture.excaliflow").write_text(json.dumps(doc, indent=1))
print(len(els), "elements")
