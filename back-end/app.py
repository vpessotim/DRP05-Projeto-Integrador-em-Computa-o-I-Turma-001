from flask import Flask, render_template, request, redirect, url_for, abort
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from models import Usuario
from db import db
from sqlalchemy.exc import IntegrityError
from functools import wraps

# --- CONFIGURAÇÃO DO APLICATIVO ---
# Criando a instância do aplicativo
app = Flask(__name__)
# Chave mestra para assinar cookies de sessão. Em produção, use variáveis de ambiente.
app.secret_key = 'ninguemsabe'

# Inicializa o Bcrypt para hashing de senhas
bcrypt = Bcrypt(app)

def requer_nivel(nivel_necessario):
    def decorador(f):
        @wraps(f) # Preserva a identidade da função original para o Flask
        def decorated_function(*args, **kwargs):
            # 1. Verifica se está logado
            if not current_user.is_authenticated:
                return lm.unauthorized()
            
            # 2. Verifica se o nível do usuário é o exigido
            # Se for admin, ele acessa tudo. Caso contrário, checa o nível específico.
            if current_user.nivel != 'admin' and current_user.nivel != nivel_necessario:
                return "Acesso Negado: Você não tem permissão para esta área.", 403
            
            return f(*args, **kwargs)
        return decorated_function
    return decorador

# Configuração do Flask-Login para gerenciar de login
lm = LoginManager(app)
lm.login_view = 'login' # Define para onde o usuário é mandado se tentar acessar rota protegida
lm.login_message = "Por favor, faça login para acessar esta página."

@lm.user_loader
def user_loader(id):
    return Usuario.query.get(int(id))

# --- NOVAS ROTAS COM NÍVEL DE ACESSO ---

@app.route("/admin/painel")
@login_required
@requer_nivel('admin') # Apenas quem tem nivel='admin' entra
def painel_admin():
    return "Bem-vindo ao Painel Administrativo!"

@app.route("/editor/postar")
@login_required
@requer_nivel('editor') # Admins ou Editores entram (conforme lógica acima)
def area_editor():
    return "Área de postagem para editores."

# Configuração do banco de dados (SQLite gera um arquivo local database.db)
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///database.db"
db.init_app(app)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False # Desativa alertas de modificação para economizar recursos

# O Flask-Login exige uma função que saiba como carregar o usuário do banco através do ID salvo na sessão
@lm.user_loader
def user_loader(id):
    # O ID vem como string da sessão, convertemos para int para a query
    return Usuario.query.get(int(id))

# --- ROTAS DA APLICAÇÃO ---

# --- PÁGINA INICIAL (HOME) ---
@app.route("/")
def home():
    return render_template('home.html')

@app.route("/login", methods=['GET','POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    
    # Processamento do formulário de login
    elif request.method == 'POST':
        email = request.form.get('emailForm')
        senha_digitada = request.form.get('senhaForm')

        if not email or not senha_digitada:
            return "Por favor, preencha todos os campos."
        
        # Busca o usuário pelo e-mail informado
        user = db.session.query(Usuario).filter_by(email=email).first()

        # O erro acontece aqui se user.senha não for um hash Bcrypt válido
        try:
            # bcrypt.check_password_hash compara a senha digitada com o hash salvo (segurança máxima)
            if user and bcrypt.check_password_hash(user.senha, senha_digitada):
                login_user(user) # Cria a sessão do usuário no navegador
                return redirect(url_for('home'))
            else:
                return render_template('login_incorreto.html')
        except ValueError:
            # Captura erro se o campo 'senha' no banco não for um hash válido do Bcrypt
            return "Erro de autenticação: Senha em formato incompatível no banco. Cadastre o usuário novamente."

# --- NOVO REGISTRO DE USUÁRIO ---
@app.route("/registrar", methods=['GET', 'POST'])
def registrar():
    if request.method == 'POST':
        nome = request.form.get('nomeForm')
        email = request.form.get('emailForm')
        senha = request.form.get('senhaForm')

        # Verifica se o e-mail já existe para evitar duplicidade
        usuario_existente = Usuario.query.filter_by(email=email).first()
        
        if usuario_existente:
            return "<div><h1>Este e-mail já está cadastrado.</h1><p>Tente outro.</p></div>"
        
        # Gera o hash da senha: nunca salve senhas em texto puro!
        # .decode('utf-8') transforma o hash de bytes para string para salvar no banco
        senha_hash = bcrypt.generate_password_hash(senha).decode('utf-8')
        novo_usuario = Usuario(nome=nome, email=email, senha=senha_hash, nivel='admin')
        
        try:
            db.session.add(novo_usuario)
            db.session.commit()
            login_user(novo_usuario) # Faz o login automático após o registro bem-sucedido
            return redirect(url_for('home'))
        
        except IntegrityError:
            db.session.rollback()
            print("Erro: Este nome de usuário já está cadastrado.")

    return render_template('registrar.html')

# --- LOGOUT DE USUÁRIO (FINALIZAR A SESSÃO) ---
@app.route("/logout")
@login_required # Garante que apenas usuários logados possam acessar esta rota
def logout():
    logout_user() # Limpa o cookie de sessão do usuário
    return redirect(url_for('home'))

# --- INICIALIZAÇÃO ---
if __name__ == "__main__":
    # Garante que as tabelas sejam criadas dentro do contexto da aplicação Flask
    with app.app_context():
        db.create_all() # Cria o arquivo .db e as tabelas se elas ainda não existirem
    app.run(debug=True) # debug=True ativa o recarregamento automático ao salvar o arquivo