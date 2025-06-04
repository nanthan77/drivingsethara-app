# Use a stable Nginx Alpine image as the base
FROM nginx:1.25-alpine

# Set the working directory inside the container to Nginx's default webroot
WORKDIR /usr/share/nginx/html

# Remove any default Nginx content from the webroot
RUN rm -rf ./*

# Copy all files and folders from the build context (which should be the 'client' directory)
# into the current working directory in the container (/usr/share/nginx/html).
# This will copy 'index.html', 'styles.css' (if it exists), the 'images' folder (if it exists),
# and the 'nginx' subdirectory (containing nginx.conf).
COPY . .

# Diagnostic step: List the contents of the Nginx webroot
# This will show us if index.html and other expected files/folders (like the 'nginx' folder)
# were copied correctly from the 'client' directory.
RUN echo "Contents of /usr/share/nginx/html after COPY . . :" && ls -la /usr/share/nginx/html

# Copy the custom Nginx configuration file from the 'nginx' subdirectory (which was copied in the step above)
# into the Nginx configuration directory.
# The source path 'nginx/nginx.conf' is now relative to /usr/share/nginx/html
# So, it refers to /usr/share/nginx/html/nginx/nginx.conf
COPY nginx/nginx.conf /etc/nginx/conf.d/default.conf

# Diagnostic step: List the contents of the Nginx configuration directory
# This will show us if default.conf (our nginx.conf) was copied correctly.
RUN echo "Contents of /etc/nginx/conf.d/ after copying nginx.conf:" && ls -la /etc/nginx/conf.d/

# Nginx listens on port 80 by default
EXPOSE 80

# Healthcheck to verify Nginx is running (optional but good practice)
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost/ || exit 1

# Command to run Nginx in the foreground
CMD ["nginx", "-g", "daemon off;"]