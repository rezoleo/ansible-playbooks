# !/usr/bin/python
# -*- encoding: utf8 -*-'

#import crypt

Type_Renouvellement_annuel= ['Association','Liste','Projet','Divers']
Type_Personnel= ['PDI','Projet Individuel']

def get_uidrange(user_type):
    if user_type=='Association':
        return(1000,1999)
    elif user_type =='Liste':
        return(2000,2999)
    elif user_type =='Projet':
        return(3000,3999)
    elif user_type =='Divers':
        return(4000,4999)
    elif user_type =='PDI':
        return(5000,5999)
    elif user_type =='Projet Individuel':
        return(6000,6999)
    else:
        print("Erreur, ce n'est pas un type d'utilisateur valide ! Si il s'agit d'un nouveau type d'utilisateur, veuillez coriger les codes dans Hermes/Ansible/Playbooks concérnés")

def get_home_path(user_type,user_name,user_year):
    if user_type in Type_Renouvellement_annuel:
        return ('/home/'+user_type+'/'+user_name)
    elif user_type in Type_Personnel:
        return('/home/'+user_type+'/'+str(user_year)+'/'+user_name)
    else:
        print("Erreur, ce n'est pas un type d'utilisateur valide ! Si il s'agit d'un nouveau type d'utilisateur, veuillez coriger les codes dans Hermes/Ansible/Playbooks concérnés")


def get_expiration_date(user_type,user_year,date_année):
    if user_type in Type_Renouvellement_annuel:
        return (str(int(date_année)+1)+'_02_01')# je suppose que les passations devraient être finis le premier février, et donc dans le cas, certe improbable, que quelqu'un reprendrait le compte, on pourrait faire ça à ce moment
    if user_type in Type_Personnel:
        return(str(int(user_year)+1)+'_01_01')#on met un +1 pour la césure, et je sais str(int(...)) c'est dégueu, mais ansible transforme toutes ses entrées en str donc c'est chiant

# def checpswd(plain,hash):
#     return crypt.crypt(plain,hash)==hash

class FilterModule(object):
    '''give back filters to ansible '''
    def filters(self):
        return {
            'get_uidrange':get_uidrange,
            'get_home_path':get_home_path,
            'get_expiration_date':get_expiration_date,
            # 'checpswd':checpswd
            }
