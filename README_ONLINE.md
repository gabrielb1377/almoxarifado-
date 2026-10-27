# Almoxarifado Central — publicação no Railway (acesso pelo celular)

Este pacote é uma adaptação **do mesmo sistema** para hospedagem em contêiner.
O servidor continua sendo FastAPI + SQLite e **requer um Railway Volume**.

## Passo a passo

1. Crie/acesse sua conta em https://railway.com e escolha **New Project**.
2. Publique os arquivos deste diretório em um repositório privado no GitHub (ou use a integração do Railway para enviar o código). **Coloque os arquivos na raiz do repositório**, inclusive `Dockerfile` e `railway.json`.
3. No Railway, selecione **Deploy from GitHub repo** e escolha o repositório. Ele reconhecerá o Dockerfile.
4. **Antes de disponibilizar o site**, no serviço crie um volume em **Volumes > Add Volume** com **Mount Path: `/app/data`**. O aplicativo tem uma proteção que impede iniciar sem esse volume.
5. Em **Variables**, configure:
   - `ALMOX_ADMIN_EMAIL`: seu e-mail de login.
   - `ALMOX_ADMIN_PASSWORD`: uma senha forte e exclusiva (mínimo 12 caracteres). **Não envie a senha por chat nem a grave no repositório**.
   - `ALMOX_DB`: `/app/data/almoxarifado.db` (opcional, já está no Dockerfile).
   - `ALMOX_REQUIRE_VOLUME`: `1` (já está no Dockerfile; não desative na hospedagem).
6. Em **Settings > Networking > Generate Domain**, crie seu endereço `.up.railway.app` com HTTPS e abra-o no Chrome do Android.
7. Entre usando o e-mail e a senha configurados em Variables. O administrador é criado apenas se o banco não tiver usuários. **O servidor nunca imprime uma senha fornecida por variável**.
8. Depois de iniciar, remova `ALMOX_ADMIN_PASSWORD` das variáveis se não desejar mantê-la no serviço; sua senha de login continuará no banco como hash. Guarde sua senha em um gerenciador seguro e altere-a pelo módulo de usuários quando necessário.

## Cuidados

- **Nunca faça deploy sem volume**, nem no plano gratuito. O diretório de outros contêineres é efêmero e pode causar perda de estoque, compras e usuários.
- Mantenha **uma única réplica/worker**: o SQLite está no volume de um único serviço. Não configure múltiplas réplicas ou escalonamento horizontal.
- Faça backups periódicos do arquivo `almoxarifado.db` via recurso de volume/backups da plataforma. Para restaurar, pare o serviço e recoloque o arquivo, conferindo integridade.
- Para uso empresarial com vários usuários simultâneos, migre para PostgreSQL com testes de concorrência e revisão de segurança antes de operar com dados reais.
- O HTTPS é servido pelo domínio público da plataforma. Não use portas abertas manualmente nem HTTP para acessar o sistema.
- A publicação envolve recursos que podem ter custos após créditos gratuitos. Verifique o plano/uso na Railway antes de confirmar.
- O serviço **não foi publicado automaticamente** ao gerar este ZIP. Conecte Railway ao ChatGPT se desejar que a publicação seja feita com sua autorização via integração.

## Teste local (sem Railway)

Use os inicializadores `iniciar_windows.bat` ou `iniciar_linux_mac.sh` (eles não ativam `ALMOX_REQUIRE_VOLUME`) para desenvolvimento e testes. `pytest -q` executa os testes locais.

### Status desta entrega

Código e arquivos de implantação **preparados e testados localmente**. **Ainda não existe um endereço público ativo**, pois o serviço deve ser conectado e um projeto/volume criado em sua conta Railway. O link real será gerado pela própria plataforma depois do deploy.
