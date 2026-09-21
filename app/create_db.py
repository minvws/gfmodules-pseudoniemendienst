from app import application, container

if __name__ == "__main__":
    application.application_init()

    db = container.get_database()
    db.generate_tables()
