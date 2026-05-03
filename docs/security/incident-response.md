# Incident Response

Acest document defineste playbook-uri simple pentru demo.

## Principii

- Contain first.
- Preserve audit evidence.
- Revoke compromised credentials.
- Communicate scope and timeline.
- Document follow-up controls.

## Cont compromis

1. Revoca sesiunile active ale userului.
2. Forteaza resetarea credentialelor la identity provider.
3. Verifica audit logs pentru actiuni recente.
4. Revoca API keys create sau folosite suspect.
5. Marcheaza evenimentul ca high-risk.
6. Creeaza follow-up pentru MFA enforcement daca lipsea.

## API key compromis

1. Revoca cheia.
2. Cauta `key_prefix` in audit logs.
3. Identifica actiunile efectuate.
4. Creeaza cheie noua cu scopes minime.
5. Verifica daca cheia a aparut in logs sau repo.
6. Ruleaza secret scan.

## Document leak suspectat

1. Revoca share links active pentru document.
2. Verifica audit logs pentru download-uri.
3. Verifica tenant membership si schimbari de rol.
4. Verifica daca documentul a fost accesat prin API key.
5. Marcheaza documentul pentru review.

## Support access misuse

1. Revoca support access activ.
2. Verifica motivul, aprobarea si expirarea.
3. Cauta toate actiunile `support.*`.
4. Notifica Owner-ul tenant-ului in demo flow.
5. Creeaza remediere pentru policy sau approval workflow.

