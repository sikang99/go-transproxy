#
# Makefile for rtsp2web
#
ORG=cojam
NAME=go-transproxy
DIST=alpine-3.13
BUILD=0.0.2.1
BASE=$(ORG)/$(NAME)-$(DIST)
IMAGE=$(BASE):$(BUILD)
#-----------------------------------------------------------------------
usage:
	@echo "usage: make [local-play|docker|git]"
#-----------------------------------------------------------------------
build b:
	go build -o $(NAME) cmd/transproxy/main.go

run r:
	./$(NAME)
#-----------------------------------------------------------------------
docker d:
	@echo "make (docker) [build|run|kill]"

docker-build db:
	docker build -t $(IMAGE) .

docker-run dr:
	docker run -d \
		-p 1935:1935 \
		-p 8080:80 \
		--name $(NAME) $(IMAGE)

docker-kill dk:
	docker stop $(NAME); docker rm $(NAME)

docker-ps dp:
	docker ps -a

docker-image di:
	docker images $(BASE)

docker-clean dc:
	docker system prune -f
	docker images

docker-upload du:
	docker push $(IMAGE)
#-----------------------------------------------------------------------
git g:
	@echo "> make (git:g) [update|store]"

git-update gu:
	git add .
	git commit -a -m "$(BUILD),$(USER)"
	git push

git-store gs:
	git config credential.helper store
#-----------------------------------------------------------------------

