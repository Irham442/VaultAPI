from database import add_credential
from database import get_credentials
from database import delete_credential
from database import update_credential

# credential = []

while True:

    print("==== VaultAPI ====")
    print("1. Add credential")
    print("2. View credential")
    print("3. Update credential")
    print("4. Delete credential")
    print("5. Exit")

    pilihan = int(input("Masukan Pilihan : "))

    if pilihan == 1:
        print("==== add credential ====")
        service = input("Service : ")
        username = input("Username : ")
        password = input("Password : ")

        add_credential(service, username, password)

    elif pilihan == 2:
        print("=== List Credential ===")
        credentials = get_credentials()

        for x in credentials:
            print(f"{x[0]}. Service : {x[1]}")
            print(f"   Username : {x[2]}")
            print(f"   Password : {x[3]}")
            print()

    elif pilihan == 3:
        credential_id = input("id update : ")
        service = input("Service baru : ")
        username = input("Username baru : ")
        password = input("Password baru : ")
        update_credential(credential_id, service, username, password)



    elif pilihan == 4:
        user_delete = input("Masukan id : ")

        delete_credential(user_delete)

        print("Berhasil di hapus!!!")

    elif pilihan == 5:
        break

    elif pilihan > 5:
        print("Pilihan tidak sesuai")