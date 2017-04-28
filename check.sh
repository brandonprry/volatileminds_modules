for i in `find . | grep rb$`; do echo $i; ruby -c $i; done
