# Almoxarifado Central — controle de componentes e ordens de montagem

Aplicação web funcional **criada do zero** com FastAPI + SQLite e interface responsiva em HTML, CSS e JavaScript, sem depender de serviços pagos. O foco é o **almoxarifado de componentes**, não o cadastro de máquinas prontas.

## Como executar no Windows

1. **Extraia o ZIP inteiro** para uma pasta, por exemplo `C:\almoxarifado-central`.
2. Instale **Python 3.11 ou superior** (marque `Add Python to PATH` na instalação, se necessário).
3. Dê dois cliques no arquivo **`iniciar_windows.bat`**. Na primeira abertura, ele instala as dependências. É necessária internet nessa etapa.
4. Abra **http://127.0.0.1:8000** no navegador.
5. **No primeiro início**, o terminal mostrará o usuário `admin@local` e **uma senha aleatória**. Guarde-a: ela não reaparecerá. Se quiser defini-la antes da primeira execução, inicie no Prompt de Comando com `set ALMOX_ADMIN_PASSWORD=MinhaSenhaForte123!` e então execute o `.bat` na mesma janela.

**Importante:** não feche a janela de execução enquanto utilizar a aplicação. Os dados permanecem no banco mesmo após fechar o programa.

No Linux/macOS: `./iniciar_linux_mac.sh` ou configure um ambiente virtual e execute `python -m uvicorn main:app --host 127.0.0.1 --port 8000`.

## Módulos integrados

| Área | Funcionalidades disponibilizadas |
|---|---|
| Identidade | Login/logout, sessões por cookie HttpOnly, senhas PBKDF2, CSRF, bloqueio após tentativas de login inválidas, cadastro e desativação de usuários e permissões por perfil |
| Cadastros | Componentes, categorias, localizações (setor/corredor/estante/prateleira/gaveta), fornecedores e associações fornecedor–componente |
| Estoque | Entradas avulsas autorizadas, perdas, bloqueios, desbloqueios, saldo físico/reservado/bloqueado/disponível, histórico de movimentos |
| Montagem | Ordens com composição livre, fluxo de aprovação, disponibilidade, reserva integral ou parcial, consumo efetivo, devoluções, solicitação e aprovação de materiais adicionais |
| Compras | Pedidos, aprovação, envio, recepção parcial, rejeição de itens, idempotência de recebimentos |
| Devoluções | Triagem/inspeção de materiais devolvidos: ficam bloqueados até aprovação do almoxarifado; rejeitados aguardam descarte formal |
| Inventário | Contagem, divergência justificada, recontagem, aprovação e ajuste com trilha de auditoria |
| Gestão | Dashboard com indicadores reais, alertas de mínimo, consumo mensal, relatórios e exportação CSV, XLSX e PDF |
| Auditoria | Ações importantes com ator e data, histórico imutável pelas rotas públicas |

**Quantidade**: entradas da API aceitam até três casas decimais, como `1.500`. O banco armazena quantidades em milésimos inteiros, evitando erro de ponto flutuante. Nas respostas JSON da API, campos de quantidade (`physical`, `reserved`, `planned` etc.) vêm em **milésimos** (`1500` significa 1,5 unidade). Os preços usam centavos inteiros.

### Fluxo recomendado

1. Cadastre categorias, locais, fornecedores e componentes.
2. Configure estoque mínimo/custo e lance estoque inicial através de **Movimentações > Entrada avulsa**, usando um perfil autorizado.
3. Crie ordem de montagem, adicione **qualquer combinação de componentes**, envie e aprove.
4. Faça a reserva (não altera o estoque físico). Se estiver faltando material, abra uma compra.
5. Aprovar/enviar um pedido de compra **não aumenta estoque**. Só a confirmação do recebimento adiciona as quantidades aceitas.
6. Com materiais reservados, inicie a ordem e registre consumo parcial ou integral. O consumo reduz o saldo físico **e** a reserva na mesma transação.
7. Devoluções entram em **bloqueio de triagem**; o almoxarifado precisa inspecionar e liberar antes de reutilizar.
8. O inventário ajusta diferenças **somente depois de aprovado**, verificando se o saldo físico não mudou desde a abertura.
9. Consulte o dashboard e exporte relatórios.

### Perfis iniciais

- **Administrador**: acesso completo.
- **Gestor**: leitura, relatórios e aprovações.
- **Almoxarife**: movimentação física, reservas, inventários, conferência de recebimentos e devoluções.
- **Montador**: consulta às ordens, registra consumo, devolução e solicitações adicionais.
- **Comprador**: fornecedores, pedidos e recebimentos.
- **Auditor**: leitura de dados e da trilha de auditoria.

O administrador pode ajustar permissões dos outros perfis na página **Permissões**. Autorizações são obrigatoriamente validadas no backend. O perfil Administrador não pode ter suas permissões removidas pela interface.

## Custo de materiais

A referência de custo unitário do componente é atualizada com o valor da **última compra recebida**. Cada consumo registra uma cópia desse custo na movimentação: alterações futuras não alteram retroativamente custos já consumidos. Devoluções preservam o custo médio ponderado dos consumos anteriores da ordem. O valor do saldo físico no dashboard usa o custo de referência vigente; **não é um livro contábil FIFO/PEPS ou custo médio de estoque**.

## Segurança e persistência

- SQLite com `foreign_keys`, `CHECK`, unicidade, WAL, transações `BEGIN IMMEDIATE`, bloqueio de escrita concorrente e verificações de quantidade.
- Saldo só muda por operação registrada em `movements` dentro da mesma transação.
- Idempotência de recebimento/consumo/devolução por cabeçalho `Idempotency-Key`, além de unicidade da referência por pedido.
- Password hashing PBKDF2-HMAC-SHA256, 600.000 iterações; sessões armazenadas como hashes; token CSRF por sessão.
- Acesso restrito inicialmente ao próprio computador (`127.0.0.1`).

### Backup

Use `python backup.py` para gerar uma cópia consistente em `backups/`. **Guarde uma cópia fora do computador**. O banco ativo fica em `data/almoxarifado.db`. O arquivo `data/.csrf_key` é gerado automaticamente no primeiro login; se ele for perdido e recriado, sessões antigas deixam de funcionar, mas os registros e as senhas permanecem.

### Testes

```bash
python -m pip install -r requirements-dev.txt
python -m pytest -q
```

Há testes de integrações entre compras, recebimentos, estoque, reserva, consumo, devolução, inventário, permissões, CSRF e bloqueio de logins inválidos. Testes usam banco isolado, sem alterar o banco principal.

## Limites desta primeira versão

É uma **primeira versão funcional (MVP)**, não um ERP certificado e pronto para disponibilização pública. Ainda requer evolução para infraestrutura empresarial: migrações versionadas ao alterar futuras colunas, rotinas automáticas de backup e restauração, recuperação de senha por e-mail, anexos/documentos fiscais em armazenamento próprio, relatórios gerenciais mais abrangentes, paginação/busca remota na seleção de componentes para catálogos acima de 150 itens, indicadores por período detalhados, impressão aprimorada de relatórios, logging centralizado, multi-almoxarifado, testes de carga e implantação com HTTPS e monitoramento. A aplicação cobre cadastro de locais e **uma localização principal por componente**, não transferência física entre múltiplos depósitos.

Se precisar expor na internet ou usá-lo simultaneamente em muitos terminais, recomenda-se migrar para PostgreSQL, configurar HTTPS, backups automáticos, monitoramento e revisão de segurança por equipe técnica antes de colocar dados reais da empresa.

## Estrutura do projeto

```text
almoxarifado_sistema/
├── main.py                # Rotas e lógica de negócio
├── db.py                  # Esquema, saldos, transações e autenticação
├── static/
│   ├── index.html         # Casca da aplicação web
│   ├── styles.css         # Layout responsivo
│   └── app.js             # Integração UI com API
├── tests/test_workflows.py
├── backup.py
├── iniciar_windows.bat
├── iniciar_linux_mac.sh
├── requirements.txt
├── requirements-dev.txt
└── data/                  # Banco gerado no primeiro início (vazio no ZIP)
```

Documentação técnica interativa após iniciar: **http://127.0.0.1:8000/docs**.

### Concorrência

As operações que alteram estoque usam escrita serializada no SQLite (`BEGIN IMMEDIATE`). O teste de concorrência executa duas reservas simultâneas para a última quantidade em estoque e verifica que **somente uma** é confirmada.
