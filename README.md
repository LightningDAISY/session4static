# session4static

## nginx.conf

    location /static/files {
        access_by_lua_file /var/www/session4static/lib/sfs.lua;
    }

