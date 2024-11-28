# Documentação da API do Servidor - Framework de Software

Caio Vinicius de Souza Costa - 836467

Diogo Vitor Oliveira Leme -836846

Gustavo Cardoso Ribeiro - 833588

## Visão Geral
Este projeto é um servidor API construído com o Framework Ktor e linguagem Kotlin. Ele fornece autenticação de usuários, incluindo o tratamento de payloads descriptografados por AES e a geração de tokens JWT para comunicação segura entre cliente e servidor.

---

## Pré-requisitos
1. **Java Development Kit (JDK):** Certifique-se de que o JDK 8 ou superior esteja instalado.
2. **Kotlin:** O servidor foi desenvolvido em Kotlin. Garanta que você tenha um ambiente compatível.
3. **Banco de Dados MySQL:** Configure um banco de dados MySQL com as tabelas necessárias.
4. **Postman/Insomnia:** Use uma ferramenta para testar os endpoints da API.

---

## Padrões de Projeto Utilizados

Este projeto implementa os seguintes **padrões de projeto**:

1. **Singleton**:
   - **Onde**: `DatabaseFactory`
   - **Descrição**: Garante que a conexão com o banco de dados seja criada apenas uma vez durante o ciclo de vida da aplicação, centralizando a configuração e economizando recursos.
   - **Exemplo**:
     ```kotlin
     object DatabaseFactory {
         fun init() {
             Database.connect(
                 url = "jdbc:mysql://localhost:3306/framework_software_db",
                 driver = "com.mysql.cj.jdbc.Driver",
                 user = "root",
                 password = "framework"
             )
         }
     }
     ```

2. **Factory Method**:
   - **Onde**: `UserFactory`
   - **Descrição**: Fornece uma interface para criar objetos do tipo `User`. Permite a abstração da lógica de criação, facilitando futuras alterações no processo de instância.
   - **Exemplo**:
     ```kotlin
     interface UserFactory {
         fun createUser(id: String, username: String, email: String): User
     }

     class DefaultUserFactory : UserFactory {
         override fun createUser(id: String, username: String, email: String): User {
             println("Criando usuário com Factory")
             return User(id, username, email)
         }
     }
     ```

3. **Strategy**:
   - **Onde**: Validação de senha (`PasswordValidationStrategy`)
   - **Descrição**: Permite que diferentes estratégias de validação de senha sejam implementadas. No projeto, o padrão é utilizado para encapsular a lógica de validação de senhas usando o algoritmo BCrypt.
   - **Exemplo**:
     ```kotlin
     interface PasswordValidationStrategy {
         fun isValid(rawPassword: String, userIdentifier: String, hashedPassword: String): Boolean
     }

     class BCryptValidationStrategy : PasswordValidationStrategy {
         override fun isValid(rawPassword: String, userIdentifier: String, hashedPassword: String): Boolean {
             val salt = "gate${userIdentifier}keepr"
             val saltedPassword = salt + rawPassword
             return BCrypt.checkpw(saltedPassword, hashedPassword)
         }
     }
     ```

---

## Configuração do Banco de Dados
Execute os seguintes scripts SQL para criar as tabelas necessárias:

```sql
CREATE TABLE users_tbl (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    identifier VARCHAR(50) NOT NULL,
    password_hash VARCHAR(64) NOT NULL
);

CREATE TABLE domains_tbl (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    domain VARCHAR(200) NOT NULL
);

CREATE TABLE users_domains_tbl (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    domain_id INT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users_tbl(id),
    FOREIGN KEY (domain_id) REFERENCES domains_tbl(id)
);
```

---

## Instalação
1. Clone o repositório:
   ```bash
   git clone https://github.com/Cvsc16/server_framework.git
   ```
2. Navegue até o diretório do projeto:
   ```bash
   cd <project_directory>
   ```
3. Certifique-se de que a configuração do banco de dados está correta no arquivo DatabaseFactory:
   ```properties
   object DatabaseFactory {
    fun init() {
        Database.connect (
            url = "jdbc:mysql://localhost:3306/framework_software_db",
            driver = "com.mysql.cj.jdbc.Driver",
            user = "root",
            password = "framework"
         )
      }
   }

4. Compile o projeto:
   ```bash
   ./gradlew build
   ```
5. Execute o servidor:
   ```bash
   ./gradlew run
   ```

---

## Endpoints da API
### POST `/v1/login`
- **Descrição:** Autentica o usuário e gera um token JWT.
- **Cabeçalhos:**
  - `Content-Type: application/json`
- **Corpo da Requisição (criptografado com AES):**
  ```json
  {
      "domain": "www.example.com",
      "auth": {
          "user_identifier": "example_user",
          "user_password": "example_password"
      }
  }
  ```
- **Resposta:**
  - **Sucesso:**
    - Status: `201 Created`
    - Corpo: Token JWT em texto simples.
  - **Falha:**
    - Status: `401 Unauthorized`
    - Corpo: `"Invalid credentials or unauthorized access to domain"`

---

## Como Funciona
1. **Descriptografia AES:**
   - O payload é descriptografado usando a chave AES e IV configurados.
2. **Hash de Senha:**
   - A senha do usuário é concatenada com um salt dinâmico e hashada com BCrypt (`gate<identifier>keepr`).
3. **Verificação no Banco de Dados:**
   - Verifica se o usuário existe e está autorizado para o domínio fornecido.
4. **Geração de Token JWT:**
   - Em caso de login bem-sucedido, gera um token JWT válido por uma semana.

---

## Teste
1. Criptografe o payload de exemplo no site [DevGlan AES Encryption/Decryption](https://www.devglan.com/online-tools/aes-encryption-decryption). Use os seguintes parâmetros:
   - **Key:** `changeit key2024`
   - **IV:** `1234567890123456`
   - **Mode:** `AES/CBC/PKCS5Padding`
   - **Output:** Base64

1. Use uma ferramenta como Postman ou Insomnia para enviar uma requisição POST para:
   ```
   http://localhost:8080/v1/login
   ```
2. Criptografe o corpo da requisição usando AES com a mesma chave e IV configurados no servidor.
3. Copie o JWT da resposta e decodifique-o em https://jwt.io para verificar as claims.

---

## Problemas Conhecidos
1. **Assinatura Inválida:** Certifique-se de que a chave secreta e a configuração do JWT correspondam no servidor e no verificador.
2. **Erros de Descriptografia:** Verifique o comprimento da chave AES (deve ter 16 caracteres) e assegure-se de que o IV está correto.




