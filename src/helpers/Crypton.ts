import * as crypto from 'crypto'

export class CryptonSecurity {
  static algorithm = 'aes-256-cbc'
  static iv = '1234567890abcdef1234567890abcdef'

  static key(key: string): Buffer {
    return crypto.createHash('sha256').update(key).digest()
  }
  static encrypt(secretKey: string, encryptionKey: string): string {
    const cipher = crypto.createCipheriv(this.algorithm, this.key(encryptionKey), Buffer.from(this.iv, 'hex'))
    let encrypted = cipher.update(secretKey, 'utf8', 'hex')
    encrypted += cipher.final('hex')
    return encrypted
  }

  static decrypt(encryptedSecretKey: string, encryptionKey: string): string {
    const decipher = crypto.createDecipheriv(this.algorithm, this.key(encryptionKey), Buffer.from(this.iv, 'hex'))
    let decrypted = decipher.update(encryptedSecretKey, 'hex', 'utf8')
    decrypted += decipher.final('utf8')
    return decrypted
  }

  static generateRandom(length: number = 40): string {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'

    let password = ''
    const bytes = crypto.randomBytes(length)

    for (let i = 0; i < length; i++) {
      password += chars[bytes[i] % chars.length]
    }
    return password
  }
}
