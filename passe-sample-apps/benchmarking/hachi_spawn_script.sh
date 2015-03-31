for i in $(seq 0 1 $((PASSE_WORKERS - 1)))
do
    /tmp/hachi_view_2831302C29 $i &
    python manage.py spawnhelpers $i &
done
gunicorn -w $PASSE_WORKERS -b 0.0.0.0:8000 benchapp.wsgi_passe:application

