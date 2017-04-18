for i in `find . | grep rb$`; do ruby -c $i; done
