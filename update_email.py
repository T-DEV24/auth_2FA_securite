from db.connection import get_collection

result = get_collection("users").update_one(
    {"user_id": "u001"},
    {"$set": {"email": "tcheuatatcheudjoclotaire@gmail.com"}}
)
print("Documents trouvés :", result.matched_count)
print("Documents modifiés :", result.modified_count)