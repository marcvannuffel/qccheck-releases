#!/usr/bin/env bash
# QCCheck – macOS-Installer (App + Kommandozeile), nach dem Muster von PodcastMagic 360. Apple Silicon und Intel.
# Zeile für Kunden (von der Installationsseite, GitHub Pages von qccheck-releases):
#   curl -fsSL https://marcvannuffel.github.io/qccheck-releases/install.sh | bash
# Die Pakete kommen öffentlich aus den GitHub-Releases von marcvannuffel/qccheck-releases (ohne Anmeldung); sicher
# macht es die Ed25519-Signatur, nicht der Ort.
# Installiert nach ~/Library/Application Support/QCCheck (aktualisiert sich von dort):
#   - die App "QCCheck.app" in ~/Applications: Electron 36.9.5 von electron/electron (SHA-256 geprüft), umbenannt,
#     mit dem Starter, ad hoc auf diesem Mac signiert – ohne Administrator-Passwort;
#   - die Kommandozeile ~/.local/bin/qccheck (Electron als Node).
# Entpackt wird nur bei gültiger Ed25519-Signatur (.sig), behalten nur, wenn VERSION und FILES.sha256 stimmen.
set -euo pipefail
REPO="marcvannuffel/qccheck-releases"
# beta: tools/installer/make-beta ersetzt nur diese Zeile (neueste Vorabversion statt releases/latest)
CHANNEL=stable
# Öffentliche Hälfte des Release-Schlüssels (SPKI, base64) – dieselbe wie in src/release-key.js; tools/release-key setzt sie
release_key="MCowBQYDK2VwAyEAnqPSW7XL2BSTimnHn7YHM7XCi/ZntpIfb/BOnNZH8i0="
electron_version="36.9.5"
electron_sha_arm64="73eb08fd541e6105d448735f2f820a7e0f63ff07e836ca05462dc2c01028e7df"
electron_sha_x64="fce84ddaba4999b83c0501f9e4bbbf811965b76b67ad81452bc918db88c09c61"

verify_sig() {
  perl - "$@" <<'PERL'
use strict; use warnings;
use Math::BigInt try => 'GMP';
use Digest::SHA; use MIME::Base64;
my ($file, $sigfile, $spki64) = @ARGV;
my $p = Math::BigInt->new(2)->bpow(255)->bsub(19);
my $ord = Math::BigInt->new(2)->bpow(252)->badd('27742317777372353535851937790883648493');
sub md { my $r = $_[0] % $p; return $r; } # floored: never negative
sub inv { return md($_[0])->bmodpow($p - 2, $p); }
sub from_le { return Math::BigInt->new('0x' . unpack('H*', scalar reverse $_[0])); }
sub enc32 { my $h = substr($_[0]->as_hex, 2); $h = ('0' x (64 - length $h)) . $h; return scalar reverse pack('H*', $h); }
my $dc = md(Math::BigInt->new(-121665) * inv(Math::BigInt->new(121666)));
my $dc2 = md($dc * 2);
my $e14 = ($p - 1) / 4; my $e38 = ($p + 3) / 8;
my $sqrtm1 = Math::BigInt->new(2)->bmodpow($e14, $p);
# a point in extended coordinates X, Y, Z, T (x = X/Z, y = Y/Z, x*y = T/Z)
sub padd {
  my ($u, $v) = @_;
  my $ea = md(($u->[1] - $u->[0]) * ($v->[1] - $v->[0]));
  my $eb = md(($u->[1] + $u->[0]) * ($v->[1] + $v->[0]));
  my $ec = md($u->[3] * $dc2 * $v->[3]);
  my $ed = md($u->[2] * 2 * $v->[2]);
  my ($ee, $ef, $eg, $eh) = ($eb - $ea, $ed - $ec, $ed + $ec, $eb + $ea);
  return [md($ee * $ef), md($eg * $eh), md($ef * $eg), md($ee * $eh)];
}
sub pmul {
  my ($u, $k) = @_;
  my $acc = [Math::BigInt->new(0), Math::BigInt->new(1), Math::BigInt->new(1), Math::BigInt->new(0)];
  for my $bit (split //, substr($k->as_bin, 2)) {
    $acc = padd($acc, $acc);
    $acc = padd($acc, $u) if $bit eq '1';
  }
  return $acc;
}
# a 32-byte encoding as a point, or undef when it is none
sub decode {
  my $raw = shift;
  my $sign = ord(substr($raw, 31, 1)) >> 7;
  substr($raw, 31, 1) = chr(ord(substr($raw, 31, 1)) & 0x7f);
  my $y = from_le($raw);
  return undef if $y >= $p;
  my $y2 = md($y * $y);
  my $x2 = md(($y2 - 1) * inv($dc * $y2 + 1));
  my $x = $x2->copy->bmodpow($e38, $p);
  $x = md($x * $sqrtm1) unless md($x * $x - $x2)->is_zero;
  return undef unless md($x * $x - $x2)->is_zero;
  return undef if $x->is_zero && $sign;
  $x = $p - $x if ($x->is_odd ? 1 : 0) != $sign;
  return [$x, $y, Math::BigInt->new(1), md($x * $y)];
}
sub encode {
  my $u = shift;
  my $zi = inv($u->[2]);
  my ($x, $y) = (md($u->[0] * $zi), md($u->[1] * $zi));
  my $out = enc32($y);
  substr($out, 31, 1) = chr(ord(substr($out, 31, 1)) | 0x80) if $x->is_odd;
  return $out;
}
open(my $fh, '<', $sigfile) or exit 1;
my $sig = decode_base64(do { local $/; <$fh> });
close $fh;
my $spki = decode_base64($spki64);
# SPKI of an Ed25519 key: 12 fixed bytes, then the 32-byte key
exit 1 unless length($sig) == 64 && length($spki) == 44 && unpack('H24', $spki) eq '302a300506032b6570032100';
my $pub = substr($spki, 12);
my $pa = decode($pub) or exit 1;
my $s = from_le(substr($sig, 32));
exit 1 if $s >= $ord;
my $sha = Digest::SHA->new(512);
$sha->add(substr($sig, 0, 32), $pub);
$sha->addfile($file, 'b');
my $k = from_le($sha->digest) % $ord;
my $base = decode(enc32(md(Math::BigInt->new(4) * inv(Math::BigInt->new(5)))));
# [S]B - [k]A must give R, the first half of the signature
my $nega = [md($p - $pa->[0]), $pa->[1], $pa->[2], md($p - $pa->[3])];
exit(encode(padd(pmul($base, $s), pmul($nega, $k))) eq substr($sig, 0, 32) ? 0 : 1);
PERL
}

# --- package check begin ---
check_package() {
  local dir="$1" version="$2" inside line want rel n=0
  inside="$(tr -d ' \r\n' < "$dir/VERSION" 2>/dev/null || true)"
  [[ "$inside" == "$version" ]] || { echo "Paket ist Version '$inside', nicht $version - nichts installiert." >&2; return 1; }
  [[ -f "$dir/FILES.sha256" ]] || { echo "Paket ohne Dateiliste (FILES.sha256) - nichts installiert." >&2; return 1; }
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ -z "${line//[[:space:]]/}" ]] && continue
    [[ "$line" =~ ^([0-9a-f]{64})\ [\ *](.+)$ ]] || { echo "Dateiliste unlesbar - nichts installiert." >&2; return 1; }
    want="${BASH_REMATCH[1]}"; rel="${BASH_REMATCH[2]#./}"
    if [[ "$rel" == /* || "$rel" =~ (^|/)\.\.(/|$) ]]; then echo "Dateiliste: unerwarteter Pfad $rel - nichts installiert." >&2; return 1; fi
    [[ -f "$dir/$rel" && "$(shasum -a 256 "$dir/$rel" | cut -d' ' -f1)" == "$want" ]] ||
      { echo "$rel passt nicht zur Dateiliste - nichts installiert." >&2; return 1; }
    n=$((n + 1))
  done < "$dir/FILES.sha256"
  [[ $n -gt 0 ]] || { echo "Dateiliste leer - nichts installiert." >&2; return 1; }
  # wie app/update.mjs und starter/verify.cjs: SHA-256 der nicht leeren Zeilen, mit \n verbunden (ohne letztes \n)
  printf '{"version":"%s","list":"%s"}' "$version" "$(grep -v '^[[:space:]]*$' "$dir/FILES.sha256" | perl -pe 'chomp if eof' | shasum -a 256 | cut -d' ' -f1)" > "$dir/.qc-verified"
}
version_newer() {
  local IFS=. i; local -a a=($1) b=($2)
  for i in 0 1 2; do
    (( 10#${a[i]} > 10#${b[i]} )) && return 0
    (( 10#${a[i]} < 10#${b[i]} )) && return 1
  done
  return 1
}
# --- package check end ---

[[ "$release_key" != __* ]] || { echo "Dieser Installer hat noch keinen Release-Schluessel (tools/release-key) - nichts installiert." >&2; exit 1; }
get() { curl -fsSL -H "User-Agent: qccheck-install" "$@"; }
# latest.json liegt als Asset in jedem Release: stabil über releases/latest (nie eine Vorabversion), Beta über die
# neueste Vorabversion der Release-Liste. Nur zum Testen: QC_INSTALL_TEST_BASE (<Quelle>/latest.json und
# <Quelle>/download/<datei>) und QC_INSTALL_TEST_KEY – beide melden sich laut.
BASE="${QC_INSTALL_TEST_BASE:-}"
if [[ -n "$BASE" ]]; then
  [[ -n "${QC_INSTALL_TEST_KEY:-}" ]] && release_key="$QC_INSTALL_TEST_KEY"
  echo "TESTMODUS: Quelle $BASE. Nicht fuer Kunden." >&2
  feed_url="$BASE/latest.json"
elif [[ "$CHANNEL" == beta ]]; then
  tag="$(get "https://api.github.com/repos/$REPO/releases?per_page=50" | perl -MJSON::PP -e '
    local $/; my $list = eval { JSON::PP::decode_json(<STDIN>) } || [];
    my @v = sort { my @a = split /\./, $a; my @b = split /\./, $b; $a[0] <=> $b[0] || $a[1] <=> $b[1] || $a[2] <=> $b[2] }
      map { $_->{tag_name} =~ /^v(\d+\.\d+\.\d+)$/ ? $1 : () }
      grep { ref $_ eq "HASH" && $_->{prerelease} && !$_->{draft} } (ref $list eq "ARRAY" ? @$list : ());
    print $v[-1] // "";')"
  [[ "$tag" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "Keine Beta-Version gefunden. / No beta release found." >&2; exit 1; }
  echo "BETA: $tag ist eine Vorabversion. / $tag is a pre-release." >&2
  feed_url="https://github.com/$REPO/releases/download/v$tag/latest.json"
else
  feed_url="https://github.com/$REPO/releases/latest/download/latest.json"
fi
json="$(get "$feed_url")"
version="$(printf '%s' "$json" | perl -MJSON::PP -e 'local $/; my $j = decode_json(<STDIN>); print $j->{version} // ""')"
name="$(printf '%s' "$json" | perl -MJSON::PP -e 'local $/; my $j = decode_json(<STDIN>); print $j->{packages}{macos} // ""')"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "Unerwartete Version '$version'." >&2; exit 1; }
[[ "$name" == "qccheck-$version-macos.tar.gz" ]] || { echo "Unerwarteter Paketname '$name'." >&2; exit 1; }

app="$HOME/Library/Application Support/QCCheck"
mkdir -p "$app"
printf '{"channel":"%s"}' "$CHANNEL" > "$app/channel.json"
installed="$(perl -MJSON::PP -e 'local $/; open my $f, "<", $ARGV[0] or exit; my $j = eval { decode_json(<$f>) }; print $j->{version} // ""' "$app/current.json" 2>/dev/null || true)"
if [[ "$installed" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] && version_newer "$installed" "$version" && [[ "${QC_INSTALL_DOWNGRADE:-}" != 1 ]]; then
  echo "Installiert ist $installed, neuer als $version - Version bleibt. Aeltere nur mit QC_INSTALL_DOWNGRADE=1." >&2; exit 1
fi
echo "QCCheck $version wird installiert ..."
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
dl="https://github.com/$REPO/releases/download/v$version"; [[ -n "$BASE" ]] && dl="$BASE/download"
get -o "$tmp/$name" "$dl/$name"
get -o "$tmp/$name.sig" "$dl/$name.sig"
echo "Signatur wird geprueft ..."
verify_sig "$tmp/$name" "$tmp/$name.sig" "$release_key" ||
  { echo "Signatur ungueltig - Paket nicht von QCCheck signiert oder beschaedigt. Nichts installiert." >&2; exit 1; }
dir="$app/versions/$version"
rm -rf "$dir"; mkdir -p "$dir"
tar -xzf "$tmp/$name" -C "$dir"
check_package "$dir" "$version" || { rm -rf "$dir"; exit 1; }
xattr -dr com.apple.quarantine "$dir" 2>/dev/null || true
printf '{"version":"%s"}' "$version" > "$app/current.json"
# Für die Update-Prüfung der App: woher (GitHub-Repo; im Testmodus die Testquelle)
if [[ -n "$BASE" ]]; then perl -MJSON::PP -e 'print JSON::PP->new->canonical->encode({ base => $ARGV[0] })' "$BASE" > "$app/install.json"
else perl -MJSON::PP -e 'print JSON::PP->new->canonical->encode({ repo => $ARGV[0] })' "$REPO" > "$app/install.json"; fi
chmod 600 "$app/install.json"

# --- die App: Electron als "QCCheck.app", der Starter als Contents/Resources/app
if [[ "$(sysctl -n hw.optional.arm64 2>/dev/null || echo 0)" == "1" ]]; then
  electron_platform="darwin-arm64"; electron_sha="$electron_sha_arm64"
else
  electron_platform="darwin-x64"; electron_sha="$electron_sha_x64"
fi
bundle="$HOME/Applications/QCCheck.app"
bundle_id="com.dudagroup.qccheck"
marker="$bundle/Contents/Resources/qc-electron"
if [[ "$(cat "$marker" 2>/dev/null || true)" != "$electron_version-$electron_platform" || ! -x "$bundle/Contents/MacOS/Electron" ]]; then
  echo "Laufzeit der App wird geladen (Electron $electron_version, ca. 100 MB) ..."
  curl -fsSL -o "$tmp/electron.zip" "https://github.com/electron/electron/releases/download/v$electron_version/electron-v$electron_version-$electron_platform.zip"
  got="$(shasum -a 256 "$tmp/electron.zip" | cut -d' ' -f1)"
  [[ "$got" == "$electron_sha" ]] || { echo "Electron: falsche Pruefsumme ($got) - App nicht installiert." >&2; exit 1; }
  ditto -x -k "$tmp/electron.zip" "$tmp/electron"
  mkdir -p "$HOME/Applications"
  rm -rf "$bundle"
  mv "$tmp/electron/Electron.app" "$bundle"
  cp "$tmp/electron/LICENSE" "$tmp/electron/LICENSES.chromium.html" "$bundle/Contents/Resources/"
  printf '%s\n' "$electron_version-$electron_platform" > "$marker"
fi
res="$bundle/Contents/Resources"
rm -rf "$res/app"; mkdir -p "$res/app"
cp "$dir"/starter/* "$res/app/"
plutil -replace CFBundleName -string "QCCheck" "$bundle/Contents/Info.plist"
plutil -replace CFBundleDisplayName -string "QCCheck" "$bundle/Contents/Info.plist"
plutil -replace CFBundleIdentifier -string "$bundle_id" "$bundle/Contents/Info.plist"
for helper in "$bundle"/Contents/Frameworks/*.app; do
  id="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$helper/Contents/Info.plist" 2>/dev/null || true)"
  [[ "$id" == com.github.Electron* ]] && plutil -replace CFBundleIdentifier -string "${id/com.github.Electron/$bundle_id}" "$helper/Contents/Info.plist"
done
codesign --force --deep --sign - "$bundle" >/dev/null 2>&1 ||
  echo "Hinweis: die App liess sich nicht neu signieren (codesign) - startet sie nicht, bitte melden." >&2
xattr -dr com.apple.quarantine "$bundle" 2>/dev/null || true
touch "$bundle"
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f "$bundle" 2>/dev/null || true
desktop_link="$HOME/Desktop/QCCheck.app"
if [[ -L "$desktop_link" || ! -e "$desktop_link" ]]; then ln -sfn "$bundle" "$desktop_link" 2>/dev/null || true; fi

# --- die Kommandozeile
mkdir -p "$HOME/.local/bin"
cat > "$HOME/.local/bin/qccheck" <<'WRAP'
#!/bin/sh
# QCCheck-Kommandozeile: das Electron der App als Node mit dem CLI-Starter
ELECTRON_RUN_AS_NODE=1 exec "$HOME/Applications/QCCheck.app/Contents/MacOS/Electron" "$HOME/Applications/QCCheck.app/Contents/Resources/app/cli.cjs" "$@"
WRAP
chmod +x "$HOME/.local/bin/qccheck"

echo ""
echo "Fertig: QCCheck $version."
echo "  App: ~/Applications/QCCheck.app (Link auf dem Schreibtisch). Dateien oder Ordner ins Fenster ziehen."
echo "  Kommandozeile: ~/.local/bin/qccheck film.mxf --profile zdf"
case ":$PATH:" in *":$HOME/.local/bin:"*) ;; *) echo "  (~/.local/bin ist nicht im PATH – z. B. in ~/.zprofile: export PATH=\"\$HOME/.local/bin:\$PATH\")" ;; esac
echo "  Updates: die App meldet sie oben rechts."
echo ""
echo "Entfernen: ~/Applications/QCCheck.app, den Link auf dem Schreibtisch, ~/.local/bin/qccheck und"
echo "  $app"
echo "  $HOME/Library/Application Support/QCCheck (Einstellungen der App)"
