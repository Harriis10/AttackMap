# Synthetic normalized outbound call anchor; never executed.
def forward(target, value, transport):
    return transport.post(target + "/Api/Items/" + value)
