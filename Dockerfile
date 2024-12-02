FROM python:3.11-slim

WORKDIR /app

# Poetry 설치
RUN pip install poetry

# Poetry 가상 환경을 컨테이너 내부에 생성하지 않도록 설정
ENV POETRY_VIRTUALENVS_CREATE=false

# 프로젝트 파일 복사
COPY pyproject-docker.toml pyproject.toml

# 의존성 설치
RUN poetry install --no-root --no-dev 

# 소스 코드 복사
COPY ./src ./src

# Poetry를 통해 서버 실행
CMD ["poetry", "run", "start-server"]
