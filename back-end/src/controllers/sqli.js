import prisma from '../database/client.js'

const controller = {}

controller.login = async function(req, res) {
  const username = req.body?.username ?? ''
  const password = req.body?.password ?? ''

  try {
    const users = await prisma.$queryRaw`
      SELECT * FROM "User"
      WHERE username = ${username}
      AND password = ${password}
    `

    if(users.length > 0) {
      return res.send({
        success: true,
        message: `Bem-vindo, ${username}!`,
        flag: 'VULCOM{SQLi_Exploit_Success}',
        // OWASP Top 10:2025 A01 - Falha no Controle de Acesso:
        // SELECT * expõe todos os campos encontrados, inclusive senhas em texto puro (A04).
        result: users
      })
    }

    return res.status(401).send({
      success: false,
      message: 'Login falhou!',
      result: users
    })
  }
  catch(error) {
    console.error('ERRO NO LOGIN:', error)
    // OWASP Top 10:2025 A10 - Tratamento Inadequado de Condições Excepcionais:
    // a resposta de erro revela a consulta SQL e a estrutura interna da tabela.
    return res.status(500).send({
      success: false,
      message: 'Erro no servidor'
    })
  }
}

export default controller