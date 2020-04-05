FROM python:3

WORKDIR /app/sharkcop-webinspector

ENV port=8080

COPY requirements.txt ./

RUN pip3 install -r requirements.txt

ENTRYPOINT ["python3","app.py"]

