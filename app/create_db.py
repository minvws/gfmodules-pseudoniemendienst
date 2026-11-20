from app import application, container

if __name__ == "__main__":
    application.application_init()
    container.configure()

    db = container.get_database()
    db.generate_tables()
