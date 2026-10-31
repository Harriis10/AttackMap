# Synthetic normalized route and sink anchors; never executed.
@app.post("/Api/Items/{id}")
def upper(id):
    return database.execute(id)
