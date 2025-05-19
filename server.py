from app import create_app

app = create_app()

if __name__ == "__main__":
    context = ('keys/test/cert.pem', 'keys/test/key.pem')  # Certificat SSL
    app.run(debug = True, ssl_context=context)
