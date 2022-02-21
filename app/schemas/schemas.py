from dataclasses import fields
from flask_marshmallow import Marshmallow

ma = Marshmallow()

# Esquema de usuario

class UsuarioSchema(ma.Schema):
    class Meta:
        fields = ('id', 'usuario', 'clave')

usuario_schema = UsuarioSchema()
usuarios_schema = UsuarioSchema(many=True)        

class PeliculaSchema(ma.Schema):
    class Meta:
        fields = ('id', 'nombre', 'estreno', 'direcror', 'reparto', 'genero', 'sinopsis')

pelicula_schema = PeliculaSchema()
peliculas_schema = PeliculaSchema(many=True)

