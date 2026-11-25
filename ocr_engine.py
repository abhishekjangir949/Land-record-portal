import hashlib
import re
from pathlib import Path
from typing import Dict, List, Tuple

import cv2
import numpy as np
from PIL import Image

try:
    import pytesseract
except ImportError:
    pytesseract = None

try:
    import pypdfium2 as pdfium
except ImportError:
    pdfium = None


CORE_FIELDS = [
    "owner_name",
    "father_name",
    "survey_number",
    "khasra_number",
    "account_number",
    "village_name",
    "tehsil",
    "district",
    "land_area",
    "land_type",
    "ownership_details",
    "mutation_details",
    "registration_details",
]

FIELD_LABELS = {
    "owner_name": "Owner Name",
    "father_name": "Father / Husband Name",
    "survey_number": "Survey No.",
    "khasra_number": "Khasra / Plot No.",
    "account_number": "Khata / Account No.",
    "village_name": "Village / Mauza",
    "tehsil": "Tehsil / Taluka",
    "district": "District",
    "land_area": "Plot Area / Rakba",
    "land_type": "Land Classification",
    "ownership_details": "Ownership Details",
    "mutation_details": "Mutation / Namantaran",
    "registration_details": "Registration / Deed Info",
}


def compute_sha256(file_path: Path) -> str:
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def preprocess_image(pil_img: Image.Image) -> Image.Image:
    rgb = np.array(pil_img.convert("RGB"))
    gray = cv2.cvtColor(rgb, cv2.COLOR_RGB2GRAY)

    h, w = gray.shape
    if min(h, w) < 1200:
        scale = 1200.0 / max(min(h, w), 1)
        gray = cv2.resize(gray, None, fx=scale, fy=scale, interpolation=cv2.INTER_CUBIC)

    denoised = cv2.fastNlMeansDenoising(gray, None, 10, 7, 21)
    thresh = cv2.adaptiveThreshold(
        denoised, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 31, 15
    )
    return Image.fromarray(thresh)


def load_pages(file_path: Path) -> List[Image.Image]:
    ext = file_path.suffix.lower()
    if ext == ".pdf":
        if pdfium is None:
            raise RuntimeError("pypdfium2 is not installed to render PDF pages.")
        pdf = pdfium.PdfDocument(str(file_path))
        pages = []
        for i in range(min(len(pdf), 5)):
            bitmap = pdf[i].render(scale=2.2)
            pages.append(bitmap.to_pil())
        return pages
    return [Image.open(file_path)]


def _run_tesseract(img: Image.Image, lang: str) -> Tuple[str, float]:
    data = pytesseract.image_to_data(img, lang=lang, output_type=pytesseract.Output.DICT)
    words = []
    confs = []
    texts = data.get("text", [])
    raw_confs = data.get("conf", [])

    for txt, cf in zip(texts, raw_confs):
        clean = (txt or "").strip()
        if clean:
            words.append(clean)
            try:
                cval = float(cf)
                if cval >= 0:
                    confs.append(cval)
            except ValueError:
                pass

    avg_conf = round(sum(confs) / len(confs), 2) if confs else 0.0
    return " ".join(words), avg_conf


def run_ocr_on_file(file_path: Path) -> Tuple[str, float]:
    if pytesseract is None:
        raise RuntimeError("pytesseract is not installed.")

    pages = load_pages(file_path)
    all_texts = []
    confidences = []

    for idx, page in enumerate(pages, start=1):
        proc = preprocess_image(page)
        text = ""
        conf = 0.0
        for lang_try in ("eng+hin", "eng"):
            try:
                text, conf = _run_tesseract(proc, lang_try)
                if text.strip():
                    break
            except Exception:
                continue

        if text.strip():
            all_texts.append(f"--- Page {idx} ---\n{text}")
            confidences.append(conf)

    combined = "\n\n".join(all_texts).strip()
    overall_conf = round(sum(confidences) / len(confidences), 2) if confidences else 0.0
    return combined, overall_conf


def _extract_match(text: str, patterns: List[str]) -> str:
    for pat in patterns:
        m = re.search(pat, text, flags=re.IGNORECASE | re.MULTILINE)
        if m:
            val = re.sub(r"\s+", " ", (m.group(1) or "")).strip(" :,-.")
            if val:
                return val[:120]
    return ""


def parse_land_fields(raw_text: str) -> Dict[str, str]:
    text = raw_text or ""
    return {
        "owner_name": _extract_match(text, [
            r"(?:owner\s*name|khatedar|land\s*owner|holder\s*name|name\s*of\s*owner|स्वामी|खातेदार)\s*[:\-]?\s*([^\n\r]+)",
        ]),
        "father_name": _extract_match(text, [
            r"(?:father(?:'s)?\s*name|husband(?:'s)?\s*name|s/o|d/o|w/o|पिता|पुत्र|पत्नी)\s*[:\-]?\s*([^\n\r]+)",
        ]),
        "survey_number": _extract_match(text, [
            r"(?:survey\s*(?:no|number|#)|सर्वे\s*(?:नं|नंबर)?)\s*[:\-]?\s*([A-Za-z0-9\/\-\.]+)",
        ]),
        "khasra_number": _extract_match(text, [
            r"(?:khasra\s*(?:no|number|#)?|plot\s*(?:no|number|#)?|खसरा\s*(?:नं|नंबर)?)\s*[:\-]?\s*([A-Za-z0-9\/\-\.]+)",
        ]),
        "account_number": _extract_match(text, [
            r"(?:khata\s*(?:no|number|#)?|account\s*(?:no|number|#)?|खाता\s*(?:नं|नंबर)?)\s*[:\-]?\s*([A-Za-z0-9\/\-\.]+)",
        ]),
        "village_name": _extract_match(text, [
            r"(?:village|mauza|ग्राम|गांव)\s*[:\-]?\s*([^\n\r,]+)",
        ]),
        "tehsil": _extract_match(text, [
            r"(?:tehsil|tahsil|taluka|तहसील)\s*[:\-]?\s*([^\n\r,]+)",
        ]),
        "district": _extract_match(text, [
            r"(?:district|distt?|जिला)\s*[:\-]?\s*([^\n\r,]+)",
        ]),
        "land_area": _extract_match(text, [
            r"(?:area|rakba|extent|रकबा|क्षेत्रफल)\s*[:\-]?\s*([0-9]+(?:\.[0-9]+)?\s*(?:hectare|ha|acre|acres|bigha|sq\.?\s*m|sqm|बीघा|हेक्टेयर)?)",
        ]),
        "land_type": _extract_match(text, [
            r"(?:land\s*(?:type|classification|category)|kisam|भूमि\s*(?:प्रकार|श्रेणी)|किस्म)\s*[:\-]?\s*([^\n\r,]+)",
        ]),
        "ownership_details": _extract_match(text, [
            r"(?:ownership|share|हिस्सा|स्वामित्व)\s*[:\-]?\s*([^\n\r]+)",
        ]),
        "mutation_details": _extract_match(text, [
            r"(?:mutation|namantaran|intkal|नामांतरण|इंतकाल)\s*[:\-]?\s*([^\n\r]+)",
        ]),
        "registration_details": _extract_match(text, [
            r"(?:registration|reg(?:istration)?\s*(?:no|date)|sale\s*deed|पंजीयन|रजिस्ट्री)\s*[:\-]?\s*([^\n\r]+)",
        ]),
    }


def detect_uncertain_fields(fields: Dict[str, str], ocr_conf: float) -> List[str]:
    uncertain = []
    for key in CORE_FIELDS:
        val = (fields.get(key) or "").strip()
        if not val:
            uncertain.append(FIELD_LABELS[key])
        elif ocr_conf < 60 and key in ("owner_name", "khasra_number", "account_number", "land_area"):
            uncertain.append(f"{FIELD_LABELS[key]} (Low OCR)")
    return uncertain


def calculate_health_score(
    fields: Dict[str, str],
    ocr_conf: float,
    is_duplicate: bool = False,
    is_conflict: bool = False,
    status: str = "Needs Review",
) -> Tuple[int, str, List[str]]:
    # 1. Field Completeness (max 45 pts)
    filled_count = sum(1 for k in CORE_FIELDS if (fields.get(k) or "").strip())
    completeness_pts = round((filled_count / len(CORE_FIELDS)) * 45)

    # 2. OCR Confidence (max 30 pts)
    clamped_conf = max(0.0, min(100.0, float(ocr_conf or 0.0)))
    ocr_pts = round((clamped_conf / 100.0) * 30)

    # 3. Validation & Status Adjustment (max 25 pts)
    key_identity_ok = bool(
        (fields.get("owner_name") or "").strip()
        and ((fields.get("khasra_number") or "").strip() or (fields.get("survey_number") or "").strip())
        and ((fields.get("village_name") or "").strip() or (fields.get("district") or "").strip())
    )
    validation_pts = 15 if key_identity_ok else 5

    if status == "Final Submitted":
        validation_pts += 10
    elif status == "Verified":
        validation_pts += 7
    elif status == "Duplicate Flagged" or status == "Conflict Flagged":
        validation_pts -= 10

    # 4. Penalties for Duplicate / Conflict
    penalty = 0
    if is_duplicate:
        penalty += 25
    if is_conflict:
        penalty += 20

    raw_score = completeness_pts + ocr_pts + validation_pts - penalty
    score = max(5, min(100, int(round(raw_score))))

    uncertain = detect_uncertain_fields(fields, clamped_conf)

    # Suggested initial status if caller passes default
    suggested_status = status
    if status == "Needs Review":
        if is_duplicate:
            suggested_status = "Duplicate Flagged"
        elif is_conflict:
            suggested_status = "Conflict Flagged"
        elif score >= 75 and not uncertain:
            suggested_status = "Verified"

    return score, suggested_status, uncertain