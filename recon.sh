#!/bin/bash
DOMAIN=$1                            
DIRECTORY=${DOMAIN}_recon                            
mkdir $DIRECTORY

#assetfinder                            
echo " Now, Assetfinder"                  
assetfinder -subs-only $DOMAIN | tee $DIRECTORY/ast.txt                                
echo " "                                                       
#subfinder                               
echo " Now, Subfinder"                             
subfinder -d $DOMAIN | tee $DIRECTORY/subf.txt                             
echo " "                                                     
#amass                             
echo "Now, Amass"                             
amass enum --passive -d $DOMAIN | tee $DIRECTORY/amass.txt

#arranging files
echo " Arranging Subdomains into one"
cat $DIRECTORY/ast.txt $DIRECTORY/subf.txt $DIRECTORY/amass.txt | sort -u | tee $DIRECTORY/subdomains.txt
rm -rf $DIRECTORY/ast.txt $DIRECTORY/subf.txt $DIRECTORY/amass.txt
echo "Done "
echo " "

#httpx and httprobe
cat $DIRECTORY/subdomains.txt | httpx | tee $DIRECTORY/livesubdomains.txt
echo "httpx done"
echo "Now, filtering live subdomains and scanning open ports like 81, 8080, 8000, 8443"
cat $DIRECTORY/subdomains.txt | httprobe -p http:81 -p http:8000 -p http:8080 -p https:8443 -c 50 | tee $DIRECTORY/httprobeOpenPorts.txt
echo "httprobe done"
cat $DIRECTORY/livesubdomains.txt | httpx -title -status-code -fr -o $DIRECTORY/httpxSubdomains.txt

#aquatone
echo " Now, screenshot using aquatone"
echo " "
cd $DIRECTORY
mkdir aquatoneDatas
cd aquatoneDatas
cat ../livesubdomains.txt | aquatone
echo " "
echo " aquatone done"
cd ../../

#waybackurls
echo " Now Waybackurls"
cat $DIRECTORY/livesubdomains.txt | waybackurls | tee $DIRECTORY/wayback.txt
echo "waybackurls done "
echo " "
#gau
echo "Now Gau"
cat $DIRECTORY/livesubdomains.txt | gau | tee $DIRECTORY/gau.txt
echo " "
echo "Gau done"
#arranging content discovery files
echo "Now, arranging content discovery files"
cat $DIRECTORY/wayback.txt $DIRECTORY/gau.txt | sort -u | tee $DIRECTORY/urls.txt
rm -rf $DIRECTORY/wayback.txt $DIRECTORY/gau.txt
cat $DIRECTORY/urls.txt | uro | httpx -mc 200 | tee $DIRECTORY/live_urls.txt
cat $DIRECTORY/live_urls.txt | grep “.php” | cut -f1 -d”?” | sed ‘s:/*$::’ | sort -u | tee $DIRECTORY/php_endpoints_urls.txt

#Gather jsfilesurls
cat $DIRECTORY/live_urls.txt | grep ".js$" | uniq | sort | tee $DIRECTORY/Jsurlsfiles1.txt
echo " "
cat $DIRECTORY/live_urls.txt | subjs | sort -u | tee $DIRECTORY/Jsurlsfiles2.txt
cat $DIRECTORY/Jsurlsfiles1.txt $DIRECTORY/Jsurlsfiles2.txt | sort -u | tee $DIRECTORY/js_urls_files.txt
rm -rf $DIRECTORY/Jsurlsfiles1.txt $DIRECTORY/Jsurlsfiles2.txt
echo "js files scan completed"
#linkfinder
echo "Now linkfinder"
echo " "
cat $DIRECTORY/js_urls_files.txt | while read url; do python3 /home/kali/Desktop/Tools/tools/LinkFinder/linkfinder.py -d -i $url -o cli | tee js_endpoints.txt
echo " "
echo "linkfinder completed"

# gf pattern filter
cat $DIRECTORY/live_urls.txt | gf xss | tee $DIRECTORY/gfxss.txt
cat $DIRECTORY/live_urls.txt | gf ssrf | tee $DIRECTORY/gfssrf.txt
cat $DIRECTORY/live_urls.txt | gf ssti | tee $DIRECTORY/gfssti.txt
cat $DIRECTORY/live_urls.txt | gf sqli | tee $DIRECTORY/gfsqli.txt
cat $DIRECTORY/live_urls.txt | gf redirect | tee $DIRECTORY/gfredirect.txt
cat $DIRECTORY/live_urls.txt | gf rce | tee $DIRECTORY/gfrce.txt
cat $DIRECTORY/live_urls.txt | gf idor | tee $DIRECTORY/gfidor.txt
cat $DIRECTORY/live_urls.txt | gf lfi | tee $DIRECTORY/gflfi.txt
echo " "
mkdir $DIRECTORY/gfTool
mv $DIRECTORY/gfxss.txt $DIRECTORY/gfssrf.txt $DIRECTORY/gfssti.txt $DIRECTORY/gfsqli.txt $DIRECTORY/gfredirect.txt $DIRECTORY/gfrce.txt $DIRECTORY/gfidor.txt $DIRECTORY/gflfi.txt $DIRECTORY/gfTool/

#dirsearch
echo "Now dirsearch"
python3 /home/kali/Desktop/Tools/tools/dirsearch/dirsearch.py -u www.$DOMAIN -o $DIRECTORY/dirsearchResult.txt
# nuclei basic use
echo "Now using nuclei tool"
cat $DIRECTORY/livesubdomains.txt | nuclei -c 100 -silent -t /home/kali/Templates/nuclei-templates | tee $DIRECTORY/Nucleiresults.txt

