# Sistema de Rastreamento e Coleta de Dados

Um sistema avançado de rastreamento e coleta de dados com múltiplas funcionalidades, desenvolvido em Python.  

---

## Funcionalidades

|       | Módulo | Descrição |
|-------|--------|-----------|
| 📄 | **Consultar CNPJ** | Obtém detalhes de empresas a partir do CNPJ. |
| 🌐 | **Consultar IP** | Rastreia informações de localização e provedor de um IP. |
| 💳 | **Consultar BIN** | Identifica dados de cartões de crédito a partir dos 6 primeiros dígitos. |
| 🏠 | **Consultar CEP** | Busca endereços completos a partir de um CEP. |
| 🛡️ | **Escanear Portas TCP** | Verifica portas abertas em um host. |
| 📶 | **Ping/Traceroute** | Testa conectividade e traça rotas de rede. |
| 🔓 | **Verificar Senha Vazada** | Checa se uma senha foi exposta em vazamentos. |
| ⚠️ | **Malwares - Guia** | Módulo em manutenção (acesso restrito). |

---

## Como Executar

### Pré-requisitos
- Python 3.8+
- Bibliotecas: `requests`, `pyfiglet`, `colorama`, `termcolor`

```bash
pip install requests pyfiglet colorama termcolor
```

### Execução
```bash
python main.py
```

---

## Detalhes Técnicos

### Estrutura do Código
- **Efeitos Visuais**: Glitch text, animações de digitação e loading.  
- **APIs Utilizadas**:  
  - CNPJ: [ReceitaWS](https://receitaws.com.br)  
  - IP: [ipinfo.io](https://ipinfo.io)  
  - BIN: [binlist.net](https://binlist.net)  
  - CEP: [ViaCEP](https://viacep.com.br)  
  - Senhas: [Have I Been Pwned](https://haveibeenpwned.com)  

### Otimizações
- Multithreading para escaneamento de portas.  
- Tratamento robusto de erros e timeouts.  

---

## Exemplos de Saída

### Consulta de CNPJ
```plaintext
RAZÃO SOCIAL: EMPRESA EXEMPLO LTDA
NOME FANTASIA: EXEMPLO
SITUAÇÃO: ATIVA
CEP: 00000-000
ENDEREÇO: Rua Exemplo, 123
```

### Escaneamento de Portas
```plaintext
[ABERTA] Porta 80: http
[ABERTA] Porta 443: https
```

---

## 🛡️ Segurança e Ética

![Aviso](https://img.shields.io/badge/AVISO-LEIA_ISSO-FF0000?style=for-the-badge)  
- Este script é para fins **educacionais** e de **pentest autorizado**.  
- Não utilize para atividades ilegais.  
- APIs públicas podem ter limites de requisições.
