Last login: Wed Jun  4 08:29:29 on ttys000
nanthan@Nanthans-MacBook-Pro Dockerfile % >....                                 
nginx/nginx.conf' in the image.
COPY . .

# Diagnostic step: List files in the webroot to verify index.html is present
# This will show the contents of /usr/share/nginx/html AFTER 'COPY . .'
RUN ls -la /usr/share/nginx/html

# Copy the custom Nginx configuration.
# This copies from 'nginx/nginx.conf' (which is located in the 'nginx' subdirectory of our build context,
# i.e., 'client/nginx/nginx.conf' in the repository) to the Nginx configuration directory in the image.
COPY nginx/nginx.conf /etc/nginx/conf.d/default.conf

# Expose port 80 (Nginx default)
EXPOSE 80

# Optional: Add a healthcheck for the Nginx server
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost/ || exit 1

# Start Nginx when the container launches
CMD ["nginx", "-g", "daemon off;"]
