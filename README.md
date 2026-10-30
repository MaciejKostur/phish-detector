# Phish Detector

Detektor phishingu oparty wyłącznie o **tekst adresu URL**. Zwraca werdykt, prawdopodobieństwo i **uzasadnienie** w prostym języku. Serwis nigdy nie odwiedza podanego adresu (brak ryzyka SSRF, odpowiedź w milisekundach).

## Struktura

```
src/phish_detector/
├── features.py    # URL -> 26 cech (długość, entropia, IP, '@', punycode, słowa-wabiki...)
├── brands.py      # podszywanie się pod marki (m.in. polskie: Allegro, InPost, BLIK, mBank...)
├── data.py        # budowa zbioru z Tranco + OpenPhish
├── synth.py       # dane syntetyczne - tylko do sprawdzenia potoku
├── train.py       # podział po domenach, wybór modelu i progu
├── evaluate.py    # metryki (PR-AUC, FPR, precyzja przy realnej częstości)
├── explain.py     # wyjaśnianie decyzji metodą ablacyjną
├── predictor.py   # logika predykcji + walidacja wejścia
└── api.py         # FastAPI: POST /predict
```

## Uruchomienie (Windows / PowerShell)

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
pytest
```

### Szybki test na danych syntetycznych
```powershell
python -m phish_detector.synth --out data/synthetic.csv --n 3000
python -m phish_detector.train --data data/synthetic.csv --out models/model.joblib
uvicorn phish_detector.api:app --reload
```
Wyniki na danych syntetycznych są zawyżone i **nie nadają się do raportowania**.

### Prawdziwe dane
1. Legalne: lista Tranco (https://tranco-list.eu), plik `top-1m.csv` -> `data/raw/`.
2. Phishing: feed OpenPhish (https://openphish.com/feed.txt) -> `data/raw/openphish.txt`.
3. Zbuduj zbiór i wytrenuj:
```powershell
python -m phish_detector.data --tranco data/raw/top-1m.csv --phishing data/raw/openphish.txt --out data/dataset.csv --n 20000
python -m phish_detector.train --data data/dataset.csv --out models/model.joblib
```
Metryki zapisują się w `models/model.metrics.json`.

## Wyniki

_Uzupełnij po treningu na prawdziwych danych._

| Model | PR-AUC | Precision | Recall | FPR | Precyzja przy 1% phishingu |
|-------|--------|-----------|--------|-----|----------------------------|
| logreg | | | | | |
| hist_gb | | | | | |

## Decyzje projektowe

- **Podział po domenach** (`GroupShuffleSplit`), żeby adresy z tej samej domeny nie trafiały jednocześnie do treningu i testu.
- **Trzy zbiory:** model uczy się na train, próg wybierany jest na walidacji (najwyższy recall przy precyzji ≥ 98%), a ocena na teście.
- **Fałszywe alarmy** są raportowane osobno, bo blokowanie legalnych stron boli użytkowników najbardziej.
- **Brak cechy `https`:** w feedach phishing coraz częściej używa HTTPS, a w zbiorze zbudowanym ze sztucznych ścieżek cecha ta byłaby artefaktem konstrukcji danych.
- **Ścieżki w legalnych URL:** Tranco zawiera same domeny, więc ścieżki są dolosowywane. Bez tego model uczyłby się „jest ścieżka = phishing".

## Ograniczenia

- Tylko cechy leksykalne: brak wieku domeny (WHOIS), certyfikatu, treści strony.
- Dane testowe są zbalansowane, a w rzeczywistości phishing to ułamek ruchu. Dlatego raportowana jest też precyzja przy 1% częstości.
- Ścieżki legalnych URL są sztuczne, co może zawyżać wyniki.
- Atakujący może świadomie unikać znanych wzorców (adversarial URLs); model wymaga retreningu na świeżych feedach (drift).
- Wyjaśnienia ablacyjne (w skali log-odds, bo prawdopodobieństwo bywa nasycone) zaniżają wpływ skorelowanych cech; dokładniejszy byłby SHAP.
- Lista marek jest ręczna i niepełna.

## Pomysły na rozwój

- SHAP zamiast ablacji, LightGBM/XGBoost.
- Cechy sieciowe (wiek domeny, certyfikat) w osobnym, wolniejszym module.
- Wersja dla e-maili (treść + SPF/DKIM/DMARC) i wtyczka do przeglądarki.
