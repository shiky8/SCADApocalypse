FROM python:3.10-slim

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000

ENV MODE=cli

CMD ["sh", "-c", "if [ \"$MODE\" = 'web' ]; then python -m marketplace.app; else python __main__.py; fi"]