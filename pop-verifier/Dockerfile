FROM python:3.13-alpine AS build

WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --target=/opt/python-deps -r requirements.txt

FROM python:3.13-alpine

RUN addgroup -S verifier && adduser -S -G verifier verifier
WORKDIR /app
COPY --from=build /opt/python-deps /opt/python-deps
ENV PYTHONPATH=/opt/python-deps

# Keep the runtime image free of pip/ensurepip and their vendored packages.
RUN python - <<'PY'
from pathlib import Path
import shutil
import sysconfig

site_packages = Path(sysconfig.get_paths()["purelib"])
stdlib = Path(sysconfig.get_paths()["stdlib"])
for pattern in ("pip", "pip-*.dist-info", "setuptools", "setuptools-*.dist-info", "pkg_resources*", "wheel", "wheel-*.dist-info", "_distutils_hack"):
    for path in site_packages.glob(pattern):
        shutil.rmtree(path, ignore_errors=True) if path.is_dir() else path.unlink(missing_ok=True)
shutil.rmtree(stdlib / "ensurepip", ignore_errors=True)
for pattern in ("pip*", "easy_install*"):
    for path in Path(sysconfig.get_paths()["scripts"]).glob(pattern):
        path.unlink(missing_ok=True)
PY

COPY --chown=verifier:verifier app.py .

USER verifier
EXPOSE 9443
CMD ["python", "/app/app.py"]
