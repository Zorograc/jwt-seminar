# Dependency
- `pip install requests`
- `pip install jwt_tool`

# Do sedaj narjeno
## Docker okolje s 4 web app-i
Vsak app ima 3 endpointe: `/login`, `/admin`, `/verify`
- PyJWT 2.8.0 (Python/Flask) - port 5000
- jsonwebtoken 9.0.0 (Node.js/Express) - port 3000
- php-jwt 6.10.0 (PHP) - port 8080
- jjwt 0.12.5 (Java/Spring Boot) - port 8081


## Napad 1. `alg none`
Napadalec nastavi algoritem na none in odstrani podpis - žeton nima več veljavnega podpisa. 
- Vsi "modern" appi so zaščiteni proti temu oz. ga blokirajo.


## Brute force šibkega secreta
(nevem a je to valid attack sploh?! -> poglej skripto in reč če je ok)
Napadalec brute-forca z "besedilno datoteko z gesli". Z geslom potem napadalec podpiše lasten token s poljubnimi "zahtevami".
- Vsi appi so lahko brute forced, če nimajo v ozadju nekega limita poskusov (nevem kako se reče).
- Zadevo bi lahko rešli na način,  da po x poskusih napadalca blokiraš IP za y časa
- Prav tako lahko z account lockanjem, da po x poskusih zakleneš account za neki časa
TLDR: Brute force je dost doodoo, ker večina appov ima brute force protection.

Ostaneta še dva attacka k ju ne poznam dobro,  reče se jima: "Claim manipulation" in "RS256 -> HS256 key confusion".
Seveda če še kakšen attack najdeš mi lahko javiš in naredim.

