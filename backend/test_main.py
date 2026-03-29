import io
import pytest
from fastapi.testclient import TestClient
from main import app, redact_pii

client = TestClient(app)

# --- MAGIC BYTES ---
JPG_MAGIC = b"\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x01\x00H\x00H\x00\x00"
PNG_MAGIC = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00"
PDF_MAGIC = b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\n"
EXE_MAGIC = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"
ZIP_MAGIC = b"PK\x03\x04\x14\x00\x00\x00\x08\x00"


# ==========================================
#    [PII]
# ==========================================

def test_pii_redaction_emails_and_phones():
    dirty = "Kontakt: prezes@firma.pl, tel: +48 123 456 789 lub 987-654-321."
    clean = redact_pii(dirty)
    assert "prezes@firma.pl" not in clean
    assert "[REDACTED EMAIL]" in clean
    assert "+48 123 456 789" not in clean
    assert "[REDACTED PHONE]" in clean

def test_pii_redaction_credit_cards_and_pesel():
    dirty = "Karta: 4539-1234-5678-9012, PESEL: 90051412345"
    clean = redact_pii(dirty)
    assert "4539-1234-5678-9012" not in clean
    assert "[REDACTED CC]" in clean
    assert "90051412345" not in clean
    assert "[REDACTED PESEL]" in clean

def test_pii_no_false_positives():
    """Testuje, czy zwykłe liczby i tekst nie są omyłkowo cenzurowane."""
    safe_text = "Firma kupiła 15 laptopów za 4500 PLN w dniu 2023-10-12."
    clean = redact_pii(safe_text)
    assert clean == safe_text  # Nic nie powinno zostać zmienione


# ==========================================
#    [Dozwolone pliki]
# ==========================================

def test_upload_valid_txt():
    response = client.post("/api/upload", files={"file": ("raport.txt", io.BytesIO(b"Czysty tekst"), "text/plain")})
    assert response.status_code == 200

def test_upload_valid_csv():
    response = client.post("/api/upload", files={"file": ("dane.csv", io.BytesIO(b"id,name\n1,Test"), "text/csv")})
    assert response.status_code == 200

def test_upload_valid_md():
    response = client.post("/api/upload", files={"file": ("readme.md", io.BytesIO(b"# Hello\nMarkdown file."), "text/markdown")})
    assert response.status_code == 200

def test_upload_valid_jpg():
    response = client.post("/api/upload", files={"file": ("foto.jpg", io.BytesIO(JPG_MAGIC + b"fake_image_data"), "image/jpeg")})
    assert response.status_code == 200

def test_upload_valid_png():
    response = client.post("/api/upload", files={"file": ("grafika.png", io.BytesIO(PNG_MAGIC + b"fake_png_data"), "image/png")})
    assert response.status_code == 200

def test_upload_valid_pdf():
    response = client.post("/api/upload", files={"file": ("dokument.pdf", io.BytesIO(PDF_MAGIC + b"fake_pdf_data"), "application/pdf")})
    assert response.status_code == 200

def test_upload_valid_clean_svg():
    clean_svg = b'<svg width="100" height="100"><circle cx="50" cy="50" r="40" /></svg>'
    response = client.post("/api/upload", files={"file": ("wektor.svg", io.BytesIO(clean_svg), "image/svg+xml")})
    assert response.status_code == 200


# ==========================================
#     [XSS i Malware]
# ==========================================

def test_upload_xss_svg_script_tag():
    malicious_svg = b'<svg><script>alert("XSS");</script></svg>'
    response = client.post("/api/upload", files={"file": ("hacked.svg", io.BytesIO(malicious_svg), "image/svg+xml")})
    assert response.status_code == 415
    assert "XSS" in response.text

def test_upload_xss_svg_onload_attribute():
    malicious_svg = b'<svg onload="alert(1)"></svg>'
    response = client.post("/api/upload", files={"file": ("hacked2.svg", io.BytesIO(malicious_svg), "image/svg+xml")})
    assert response.status_code == 415
    assert "XSS" in response.text

def test_upload_unsupported_binary_exe():
    response = client.post("/api/upload", files={"file": ("wirus.exe", io.BytesIO(EXE_MAGIC), "application/x-msdownload")})
    assert response.status_code == 415

def test_upload_unsupported_archive_zip():
    response = client.post("/api/upload", files={"file": ("paczka.zip", io.BytesIO(ZIP_MAGIC), "application/zip")})
    assert response.status_code == 415

def test_upload_empty_file():
    response = client.post("/api/upload", files={"file": ("pusty.txt", io.BytesIO(b""), "text/plain")})
    # Pusty plik powinien zostać albo odrzucony, albo przetworzony jako 0 bytes, 
    # zakładamy że backend nie "wybucha" (zwraca 200 lub 400, byle nie 500)
    assert response.status_code in [200, 400, 415]


# ==========================================
#    [Oszukane rozszerzenia]
# ==========================================

def test_spoofed_txt_as_jpg():
    """Wgrywamy plik tekstowy, ale nazywamy go .jpg"""
    response = client.post("/api/upload", files={"file": ("oszust.jpg", io.BytesIO(b"To jest tekst"), "image/jpeg")})
    assert response.status_code == 415

def test_spoofed_exe_as_txt():
    """Wgrywamy plik EXE (z nagłówkiem MZ), ale nazywamy go .txt"""
    response = client.post("/api/upload", files={"file": ("wirus.txt", io.BytesIO(EXE_MAGIC), "text/plain")})
    assert response.status_code == 415

def test_spoofed_pdf_as_png():
    """Wgrywamy PDF, ale udajemy, że to PNG"""
    response = client.post("/api/upload", files={"file": ("dokument.png", io.BytesIO(PDF_MAGIC), "image/png")})
    assert response.status_code == 415

def test_spoofed_jpg_as_pdf():
    """Wgrywamy obrazek, ale udajemy, że to PDF"""
    response = client.post("/api/upload", files={"file": ("obraz.pdf", io.BytesIO(JPG_MAGIC), "application/pdf")})
    assert response.status_code == 415


# ==========================================
#    TESTY API I CYKLU ŻYCIA PLIKU
# ==========================================

def test_read_root():
    response = client.get("/")
    assert response.status_code == 200

def test_get_files_list():
    response = client.get("/api/files")
    assert response.status_code == 200
    assert isinstance(response.json().get("files", response.json()), list)

def test_download_nonexistent_file():
    response = client.get("/api/download/nieistnieje.txt")
    assert response.status_code == 404

def test_delete_nonexistent_file():
    response = client.delete("/api/files/nieistnieje.txt")
    assert response.status_code == 404

def test_batch_download_empty():
    response = client.post("/api/download-batch", json={"filenames": []})
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/zip"

def test_full_file_lifecycle():
    """Integracyjny test: Upload -> Sprawdzenie -> Usunięcie"""
    filename = "lifecycle_test.txt"
    content = b"Testowy plik cyklu zycia"
    
    # Upload
    res_upload = client.post("/api/upload", files={"file": (filename, io.BytesIO(content), "text/plain")})
    assert res_upload.status_code == 200
    
    # Sprawdzenie listy
    res_list = client.get("/api/files")
    files = res_list.json().get("files", res_list.json())
    file_names = [f["filename"] if isinstance(f, dict) else f for f in files]
    assert filename in file_names
    
    # Pobranie
    res_download = client.get(f"/api/download/{filename}")
    assert res_download.status_code == 200
    assert res_download.content == content
    
    # Usunięcie
    res_delete = client.delete(f"/api/files/{filename}")
    assert res_delete.status_code == 200
    
    # Sprawdzenie, czy zniknął
    res_list_after = client.get("/api/files")
    files_after = res_list_after.json().get("files", res_list_after.json())
    file_names_after = [f["filename"] if isinstance(f, dict) else f for f in files_after]
    assert filename not in file_names_after