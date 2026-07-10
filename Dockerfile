# =============================================================
#  커스텀 이미지: "파이썬 이미지 위에 n8n을 얹는다"
#
#  [왜 이렇게 하는가]
#  최신 공식 n8n 이미지(n8nio/n8n)는 보안 강화(Docker Hardened Image)로
#  패키지 매니저(apk)가 제거되어 있어, 그 안에 Python을 설치할 수 없다.
#  그래서 반대로, Python 공식 이미지를 베이스로 삼고 n8n을 설치한다.
#  이러면 Python이 자기 이미지의 네이티브 라이브러리(ssl 등)를 그대로 써서
#  HTTPS 통신(OpenAI/Discord 호출)이 안전하게 동작한다.
# =============================================================

# 1) 베이스: Python 공식 이미지 (Alpine 기반, apk 사용 가능)
FROM python:3.12-alpine

# 2) n8n 실행에 필요한 런타임 설치
#    - nodejs, npm : n8n은 Node.js 앱
#    - tini        : PID 1 신호 처리(좀비 프로세스 방지)
RUN apk add --no-cache nodejs npm tini

# 3) Python 라이브러리 설치
#    requirements.txt 를 먼저 복사 → 코드만 바뀔 때 빌드 캐시 재사용
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --break-system-packages -r /tmp/requirements.txt

# 4) n8n 전역 설치 (--omit=dev: 개발 의존성 제외로 용량 절약)
RUN npm install -g n8n --omit=dev && npm cache clean --force

# 5) 비root 사용자 생성 + 데이터/작업 폴더 준비
#    [왜] 컨테이너를 root로 돌리지 않는다(최소 권한 원칙).
#    /home/node/.n8n : n8n 설정/워크플로우 저장 위치(볼륨으로 영속화)
#    /data           : 우리 스크립트/로그/결과물 마운트 지점
RUN addgroup -g 1000 node 2>/dev/null || true; \
    adduser -u 1000 -G node -s /bin/sh -D node 2>/dev/null || true; \
    mkdir -p /home/node/.n8n /data && chown -R node:node /home/node /data

# 6) n8n 환경 기본값
ENV N8N_USER_FOLDER=/home/node \
    N8N_PORT=5678 \
    N8N_RUNNERS_ENABLED=true

USER node
WORKDIR /home/node
EXPOSE 5678

# tini를 PID1로 두고 n8n 기동
ENTRYPOINT ["tini", "--"]
CMD ["n8n", "start"]
