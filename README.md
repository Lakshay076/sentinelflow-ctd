# MONI

## Backend

python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

Copy-Item .env.example .env

uvicorn api.main:app --reload --port 8000


## Frontend

cd frontend
npm install
npm run dev


## API

http://localhost:8000

## Dashboard

http://localhost:5173
