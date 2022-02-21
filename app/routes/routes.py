import re
from flask import Blueprint, jsonify, request
from models.models import Usuario, Pelicula
from flask_jwt_extended import create_access_token, get_jwt_identity, jwt_required
from database import db
from schemas.schemas import pelicula_schema, peliculas_schema, usuario_schema, usuarios_schema
import bcrypt

blue_print = Blueprint('app', __name__)

# ruta de inicio
@blue_print.route('/', methods = ['GET'])
def inicio():
    return jsonify(respuesta='Rest Api Python con Flask, JWToken y Mysql-Alchemy')

# ruta de registro de usuario
@blue_print.route('/auth/registrar', methods = ['POST'])
def registrar_usuario():
    try:
        #obtener usuario y clave
        usuario = request.json.get('usuario')
        clave = request.json.get('clave')
        #verifica que si vengan los datos
        if not usuario or not clave:
            return jsonify(respuesta='Campos invaliddos '), 400
        #consulta en la BD para verificar si ya existe el usuario
        existe_usuario = Usuario.query.filter_by(usuario = usuario).first()

        if existe_usuario:
            return jsonify(respuesta='Usuario ya existe'), 400
        
        # encriptamos la clave
        clave_encriptada = bcrypt.hashpw(clave.encode('utf-8'), bcrypt.gensalt())
        #creamos el modelo para gaurdar en la BD
        nuevo_usuario = Usuario(usuario, clave_encriptada)
        db.session.add(nuevo_usuario)
        db.session.commit()

        return jsonify(respuesta='Usuario creado exitosamente con clave: ' + clave_encriptada), 201

    except Exception:
        return jsonify(respuesta='Error en la peticion'), 500

# ruta para iniciar sesion
@blue_print.route('/auth/login', methods=['POST'])
def iniciar_sesion():
    try:
        #obtener usuario y clave
        usuario = request.json.get('usuario')
        clave = request.json.get('clave')
        #verifica que si vengan los datos
        if not usuario or not clave:
            return jsonify(respuesta='Campos invaliddos '), 400
        #consulta en la BD para verificar ubicar al usuario
        existe_usuario = Usuario.query.filter_by(usuario = usuario).first()

        if not existe_usuario:
            return jsonify(respuesta='Usuario no encontrado'), 404

        clave_encriptada = bcrypt.hashpw(clave.encode('utf-8'), bcrypt.gensalt())
        
        # return jsonify(respuesta='Clave encriptada: ' + str(clave_encriptada) + 'clave en la bd: ' + existe_usuario.clave), 200
        # clave_db = existe_usuario.clave        
        # return jsonify(respuesta= 'Usuario: ' + usuario + 'Clave encriptada: ' + clave_encriptada  + 'Clave encriptada: ' + clave_encriptada  ), 200

        es_clave_valida = bcrypt.checkpw(clave.encode('utf-8'), existe_usuario.clave.encode('utf-8'))

        # es_clave_valida = bcrypt.hashpw(clave_encriptada, existe_usuario.clave.encode('utf-8')) == existe_usuario.clave.encode('utf-8')
        
        # validamos que sean iguales la claves
        if es_clave_valida:
            access_token = create_access_token(identity=usuario)
            return jsonify(access_token = access_token), 200
        else:
            return jsonify(respuesta='Clave o usuario incorrecto'), 404
        
    except Exception as e:
        print(e)        
        return jsonify(respuesta='ocurrio un error'), 500
        
# obtener usuarios
@blue_print.route('/auth/usuarios', methods=['GET'])
def obtener_usuarioss():
    try:
        usuarios = Usuario.query.all()
        respuesta = usuarios_schema.dump(usuarios)        

        return usuarios_schema.jsonify(respuesta), 200
    except Exception:
        return jsonify(respuesta='Error al crear pelicula'), 500                

# RUTAS PROTEGIDAS CON JSON_WEB_TOKEN      
# crear pelicula
@blue_print.route('/api/peliculas', methods=['POST'])
@jwt_required()
def crear_pelicula():
    try:
        nombre = request.json['nombre']
        estreno = request.json['estreno']
        director = request.json['director']
        reparto = request.json['reparto']
        genero = request.json['nombre']        
        sinopsis = request.json['sinopsis']

        nueva_pelicula = Pelicula(nombre, estreno, director, reparto, genero, sinopsis)
        db.session.add(nueva_pelicula)
        db.session.commit()

        return jsonify(respuesta='Pelicula creada'), 201
    except Exception:
        return jsonify(respuesta='Error al crear pelicula'), 500

# obtener peliculas
@blue_print.route('/api/peliculas', methods=['GET'])
@jwt_required()
def obtener_pelicualas():
    try:
        peliculas = Pelicula.query.all()
        respuesta = peliculas_schema.dump(peliculas)        

        return peliculas_schema.jsonify(respuesta), 200
    except Exception:
        return jsonify(respuesta='Error al crear pelicula'), 500     

# obtener pelicula por id
@blue_print.route('/api/peliculas/<int:id>', methods=['GET'])
@jwt_required()
def obtener_pelicuala_por_id(id):
    try:
        pelicula = Pelicula.query.get(id)
        respuesta = pelicula_schema.dump(pelicula)        

        return pelicula_schema.jsonify(respuesta), 200
    except Exception:
        return jsonify(respuesta='Error al crear pelicula para el commit'), 500             

# actualizar pelicula
@blue_print.route('/api/peliculas<int:id>', methods=['PUT'])
@jwt_required()
def actualizar_pelicula(id):
    try:
        pelicula = Pelicula.query.get(id)

        if not pelicula:
            return jsonify(respuesta='Pelicula no encontrada'), 404

        pelicula.nombre = request.json['nombre']
        pelicula.estreno = request.json['estreno']
        pelicula.director = request.json['director']
        pelicula.reparto = request.json['reparto']
        pelicula.genero = request.json['nombre']        
        pelicula.sinopsis = request.json['sinopsis']

        db.session.commit()
        return jsonify(respuesta='Pelicula actualizada'), 200

    except Exception:
        return jsonify(respuesta='Error al crear pelicula'), 500        

# weliminar pelicula 
@blue_print.route('/api/peliculas/<int:id>', methods=['DELETE'])
@jwt_required()
def eliminar_pelicuala_por_id(id):
    try:
        pelicula = Pelicula.query.get(id)

        if not pelicula:
            return jsonify(respuesta='Peluicula no encontrada'), 404

        db.session.delete(pelicula)
        db.session.commit()
        return jsonify(respuesta='Pelicula eliminada'), 200

    except Exception:
        return jsonify(respuesta='Error al crear pelicula'), 500             
