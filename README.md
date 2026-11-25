# Ambiente do trabalho prático: roteador IPv4 em software

Esta pasta é o repositório do grupo. Ela monta, com o Docker Compose, a rede da especificação do roteador publicada no Moodle: h1, r1, r2, r3, h2 e gerente. O roteador de cada grupo roda em r1, r2 e r3. A especificação é a referência de tudo o que está aqui; este arquivo só mostra por onde começar.

## Requisitos

Docker Engine 28 ou mais recente, com Docker Compose 2.36 ou mais recente. No Windows e no macOS, o Docker Desktop atual. Todos os comandos rodam nesta pasta, e cada linha `docker ...` funciona igual no terminal do Linux e no `cmd` do Windows.

## Primeiros passos

1. Suba a rede. Na primeira vez, as imagens são construídas, o que leva alguns minutos:

   ```text
   docker compose up -d --build
   ```

2. O executável `roteador/roteador` não é versionado. Cada contêiner copia os fontes e executa `build.sh` na própria cópia ao iniciar. Se o build falhar, a máquina continua no ar e `docker compose logs r1` mostra o erro. Para observar o enlace, use `docker exec -it r1 tcpdump -n -e -i eth0`.

3. O código em `roteador/` usa C++17, a biblioteca padrão e as interfaces do sistema Linux. A cada mudança no código, reinicie os roteadores para recompilar:

   ```text
   docker compose restart r1 r2 r3
   docker compose logs -f r1
   ```

4. Rode os 51 testes oficiais do professor, agrupados por parte do roteador:

   ```text
   docker compose run --rm testes
   ```

## Compilação e execução manual

Em Linux, com G++ e os cabeçalhos do sistema disponíveis, execute a partir da raiz do repositório:

```sh
cd roteador
sh build.sh
sudo ./roteador ../configuracao/r1.conf
```

O último comando pressupõe um ambiente isolado com as interfaces declaradas no arquivo de configuração. O processo precisa de privilégios para abrir sockets brutos `AF_PACKET` (`CAP_NET_RAW`, normalmente disponível ao executar como root). A topologia Docker já prepara as interfaces e concede os privilégios necessários.

## Testes do grupo

Os testes locais estão em `roteador/tests/`. Em Linux, execute a partir de `roteador/` para que o teste de configuração encontre `../configuracao/`:

```sh
test_dir=$(mktemp -d)
set --
for source in src/*.cpp; do
    [ "$source" = src/main.cpp ] || set -- "$@" "$source"
done
for test in tests/*.cpp; do
    name=$(basename "$test" .cpp)
    g++ -std=c++17 -pthread -Iinclude "$test" "$@" -o "$test_dir/$name" || exit 1
    if [ "$name" != test_send ]; then
        "$test_dir/$name" || exit 1
    fi
done
```

`test_send` é compilado pelo laço e executado separadamente. Ele transmite um quadro bruto pela `eth0`. Use somente um ambiente isolado, com `eth0` de teste e um par adequado para capturar o quadro, e execute `sudo "$test_dir/test_send"`.

## O que há aqui

| Caminho | Conteúdo |
|---|---|
| `compose.yaml` | A topologia com o roteador do grupo, os serviços `testes` e `falha` e o perfil `painel` |
| `compose-kernel.yaml` | A mesma topologia com o encaminhamento do Linux, para o experimento |
| `configuracao/` | `r1.conf`, `r2.conf` e `r3.conf`, iguais aos da seção 3 da especificação |
| `roteador/` | O código do grupo e o `Dockerfile` da imagem dos roteadores |
| `quadros/` | Quadros de exemplo em hexadecimal, para `docker exec h1 injetar /quadros/ARQUIVO` |
| `capturas/` | Onde o `tcpdump` grava as capturas, vista em `/capturas` dentro das máquinas |
| `suporte/` | Imagens e programas do ambiente: máquinas, testes, falhas, isolamento das pontes e painel. Não precisa ser alterada |

A lista completa de comandos está na seção 12 da especificação, e a lista de verificação, na seção 13.
