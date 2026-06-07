# 실행 가이드

## 1. 환경 준비

Python 3.9 이상 필요. 가상 환경 사용을 권장합니다.

**Windows**

```bash
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

**macOS / Linux**

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## 2. 실행

```bash
jupyter notebook train_full.ipynb
```

또는 VS Code에서 `train_full.ipynb` 열고 상단 **"Run All"** 클릭.

## 3. 자동 생성 파일

실행이 끝나면 노트북과 같은 폴더에 다음이 생성됩니다.

| 경로 | 내용 |
|---|---|
| `log.txt` | 노트북 실행 중 출력 로그 |
| `result.txt` | 시드, 하이퍼파라미터, 최종 메트릭 (재현성 체크용) |
| `results/` | 그래프(PNG 5장) + 메트릭(CSV 3개) |

## 4. 데이터셋

- 학습용 데이터: `data/out_full.csv` (포함됨, 노트북 실행에 충분)
- 원본 데이터셋: **MalwareBench** — https://github.com/MalwareBench/MalwareBench
- 본 CSV는 `feature_extractor/` 코드로 위 원본에서 24개 정적 피쳐를 추출한 결과

## 5. 폴더 구조

```
submission/
├── README.md
├── requirements.txt
├── train_full.ipynb          # 학습 노트북 (메인)
├── data/
│   └── out_full.csv          # 추출된 피쳐 (14,817 × 30)
└── feature_extractor/        # 피쳐 추출 파이프라인 코드
```
