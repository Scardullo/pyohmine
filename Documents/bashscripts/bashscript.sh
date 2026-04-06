#!/bin/bash
showname(){
       echo Hello $1
       if [ ${1,,} = anthony ]; then
               return 0
       else
               return 1
       fi
}
showname $1
if [ $? = 1 ]; then
       echo "Unknown"
fi


echo Enter username
read UNAME
echo Enter distribution
read DISTRO


echo Hello $UNAME you are currently using $DISTRO


if [ ${2,,} = scardullo ]; then
       echo Hello Mr. Scardullo
elif [ ${2,,} = help ]; then
       echo Enter surname
else
       echo "Unknown"
fi


case ${3,,} in
       admin | tech)
               echo "System Administrator"
               ;;
       help)
               echo "Enter Title"
               ;;
       *)
               echo "Unknown"
esac


