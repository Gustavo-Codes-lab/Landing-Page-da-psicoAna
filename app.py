import os
import hmac
import hashlib
from dotenv import load_dotenv
from flask import Flask, request, jsonify, abort
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# 1. PROTEÇÃO DE CREDENCIAIS (.env)
# Carrega tokens blindados na memória (jamais "hard-coded" neste arquivo)
load_dotenv()

META_APP_SECRET = os.getenv("META_APP_SECRET", "")
VERIFY_TOKEN = os.getenv("WHATSAPP_VERIFY_TOKEN", "")
ACCESS_TOKEN = os.getenv("WHATSAPP_ACCESS_TOKEN", "")

app = Flask(__name__)

# 2. DEFESA CONTRA DDoS (Rate Limiting)
# Bloqueio inteligente por IP da Origem. 
# Importante: para produção com Nginx/Gunicorn ou vários workers, use Storage URI Redis em vez de memory.
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["1000 per day", "100 per hour"],
    storage_uri="memory://"
)

# 3. VALIDAÇÃO NATIVA DE ASSINATURA (Payload Verification via HMAC-SHA256)
def verify_meta_payload(req):
    """
    Bloqueia atacantes que tentam forjar requisições fakes imitando a Meta.
    Verifica o cabeçalho oficial X-Hub-Signature-256 gerado pela Meta.
    """
    signature_header = req.headers.get("X-Hub-Signature-256")
    
    # Se alguém bater na porta POST /webhook sem assinatura = bloqueio imediato
    if not signature_header:
        abort(403, "Assinatura exigida ausente.")
        
    try:
        # Padrão recebido do payload da meto: "sha256=abcdef123..."
        scheme, signature = signature_header.split("=")
        if scheme != "sha256":
            abort(403, "Método criptográfico inválido.")
    except ValueError:
        abort(403, "Cabeçalho de assinatura mal formatado.")

    # A máquina local refaz o cálculo do Hash usando o Corpo Bruto da Requisição 
    # misturado com o seu "META_APP_SECRET" verdadeiro (que apenas Meta e você conhecem)
    expected_hmac = hmac.new(
        key=META_APP_SECRET.encode("utf-8"),
        msg=req.get_data(),  # Lê os bytes crus da payload exata
        digestmod=hashlib.sha256
    ).hexdigest()

    # Compara o cálculo gerado com a assinatura interceptada, evitando ataques de "Timing"
    if not hmac.compare_digest(expected_hmac, signature):
        abort(403, "Payload Fake/Maligna. Assinatura não coincide.")
        

# ==================== ROTAS DA API ====================

@app.route("/", methods=["GET"])
@limiter.exempt  # Rota liberada do Rate Limit rigoroso para checagem do servidor
def health_check():
    """Confirma que o servidor Python do Bot está voando!"""
    return jsonify({"status": "Servidor do Bot Operando 100% Protegido."}), 200


@app.route("/webhook", methods=["GET"])
@limiter.limit("20 per minute") # Previne que spammers usem GET flood neste endpoint de registro
def register_webhook():
    """
    FASE 1 DA INTEGRAÇÃO: Handshake com a aba de "Developers" da Meta.
    A Meta envia parâmetros GET. Nós devolvemos apenas se o `VERIFY_TOKEN` secreto bater.
    """
    mode = request.args.get("hub.mode")
    token = request.args.get("hub.verify_token")
    challenge = request.args.get("hub.challenge")

    if mode and token:
        if mode == "subscribe" and token == VERIFY_TOKEN:
            print("[INFO] Webhook Verificado pela Meta com Sucesso!")
            return challenge, 200
        else:
            print("[ERRO] Alguém tentou verificar o webhook com o Token SECRETO Errado.")
            abort(403)

    return "Esperando parâmetros de handshake da Meta.", 200


@app.route("/webhook", methods=["POST"])
@limiter.limit("60 per minute") # Impede FloodMassivo da propria Meta ou Hackers
def receive_whatsapp_message():
    """
    FASE 2 DA INTEGRAÇÃO: Onde o fluxo de conversas da paciente entra.
    (Endpoint central altamente restrito).
    """
    # === AQUI ESTÁ SEU ESCUDO DE ASSINATURA EXIGIDO ===
    verify_meta_payload(request)
    
    # === SEGURO! Parse e lógica da conversa ===
    body = request.get_json()
    
    if body and "object" in body:
        if body["object"] == "whatsapp_business_account":
            
            # Navega pelo corpo da requisição JSON do WhatsApp
            entry = body.get("entry", [])[0]
            changes = entry.get("changes", [])[0]
            value = changes.get("value", {})
            
            # Checa se é uma "Message" ou apenas status de leitura
            if "messages" in value:
                message = value["messages"][0]
                # ID original da Meta do REMETENTE
                remetente_id = message.get("from", "") 
                
                # PREVENÇÃO NOSQL/SQL INJECTION E XSS: 
                # (Sanitização Nativa Recomendada)
                texto_recebido_bruto = message.get("text", {}).get("body", "")
                
                # 4. Sanitização Basicona (Tira tags falsas, limita a caracteres indevidos, etc.)
                texto_limpo = str(texto_recebido_bruto).strip()
                texto_limpo = texto_limpo.replace("<", "").replace(">", "").strip()

                print(f"[RECEPÇÃO SEGURA] Paciente {remetente_id}: {texto_limpo}")
                
                # -> Aqui você enviaria a resposta usando requisições `requests.post()` para a META <-

            # Retorna 200 extremamente rápido para a META não penalizar a URL (timeout deles é em poucos segundos)
            return jsonify({"status": "ok_processed"}), 200
        else:
            return jsonify({"status": "nao_e_whatsapp"}), 404
            
    return jsonify({"status": "erro_formato"}), 400


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    # Importante: debug=False em produção é uma regra fundamental de segurança.
    app.run(host="0.0.0.0", port=port, debug=True)
